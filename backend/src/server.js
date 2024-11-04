const express = require("express");
const rateLimit = require("express-rate-limit");
const bodyParser = require("body-parser");
const axios = require("axios");
const { MongoClient } = require("mongodb");
const validator = require("validator");
const emailParser = require("email-parser");
const simpleParser = require('mailparser').simpleParser;
require("dotenv").config({ path: "../.env" });

const app = express();
const port = process.env.PORT || 3002;

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

// Middleware
app.use(bodyParser.json({ limit: '50mb' }));
app.use(limiter);

// MongoDB connection
let db;
const connectDB = async () => {
  try {
    const client = await MongoClient.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log("Connected to MongoDB");
    db = client.db("Datashield");
    return client;
  } catch (err) {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  }
};

const validateUrl = (url) => {
  return validator.isURL(url, {
    protocols: ['http', 'https'],
    require_protocol: true
  });
};

const validateEmail = (email) => {
  return validator.isEmail(email);
};

const fetchUrlContent = async (url) => {
  try {
    const response = await axios.get(url, {
      timeout: 5000,
      maxRedirects: 5,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityAnalyzer/1.0;)'
      }
    });
    return response.data;
  } catch (error) {
    throw new Error(`Failed to fetch URL content: ${error.message}`);
  }
};

// Email Analysis Functions
const extractEmailMetadata = async (emailContent) => {
  try {
    const parsed = await simpleParser(emailContent);
    return {
      from: parsed.from?.text,
      subject: parsed.subject,
      date: parsed.date,
      headers: parsed.headers,
      attachments: parsed.attachments?.length || 0,
      hasHtml: !!parsed.html,
      links: extractLinks(parsed.html || ''),
      spfResult: parsed.headers.get('authentication-results') || 'Not available',
      dkimResult: parsed.headers.get('dkim-signature') ? 'Present' : 'Not present',
      returnPath: parsed.headers.get('return-path'),
    };
  } catch (error) {
    throw new Error(`Failed to parse email: ${error.message}`);
  }
};

const extractLinks = (htmlContent) => {
  const linkRegex = /href=["'](https?:\/\/[^"']+)["']/g;
  const links = [];
  let match;
  while ((match = linkRegex.exec(htmlContent)) !== null) {
    links.push(match[1]);
  }
  return links;
};

const analyzeEmailSecurity = async (metadata) => {
  const suspiciousIndicators = [];

  // Check sender domain reputation
  if (metadata.from) {
    const domain = metadata.from.split('@')[1];
    // Add domain reputation check logic here
  }

  // Check for suspicious patterns
  if (metadata.subject?.toLowerCase().includes('urgent') ||
      metadata.subject?.toLowerCase().includes('password')) {
    suspiciousIndicators.push('Suspicious subject keywords');
  }

  if (metadata.links.length > 0) {
    const suspiciousLinks = metadata.links.filter(link => 
      link.includes('bit.ly') || 
      link.includes('tinyurl') ||
      link.includes('shortened')
    );
    if (suspiciousLinks.length > 0) {
      suspiciousIndicators.push('Contains suspicious shortened links');
    }
  }

  return suspiciousIndicators;
};

app.get("/health", (req, res) => {
  res.status(200).json({ 
    status: "healthy", 
    timestamp: new Date().toISOString() 
  });
});

app.get("/", (req, res) => {
  res.send("Security Analysis Server running. Available endpoints: POST /analyze-url, POST /analyze-email");
});

app.post("/analyze-url", async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  if (!validateUrl(url)) {
    return res.status(400).json({ error: "Invalid URL format" });
  }

  try {
    const urlContent = await fetchUrlContent(url);

    const data = {
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content: `Analyze the following URL and its content for phishing indicators. 
                   Provide a risk assessment percentage and a brief explanation in under 50 characters.
                   Consider: domain age, SSL status, content legitimacy, and known patterns.`
        },
        {
          role: "user",
          content: `URL: ${url}\nContent: ${urlContent}`
        }
      ]
    };

    const response = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      data,
      {
        headers: {
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        },
        timeout: 10000
      }
    );

    const result = response.data.choices[0].message.content;

    await db.collection("urlAnalysis").insertOne({
      url,
      result,
      timestamp: new Date(),
      ip: req.ip
    });

    res.json({
      url,
      analysis: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error("Error analyzing URL:", {
      url,
      error: error.message,
      timestamp: new Date().toISOString()
    });

    res.status(500).json({
      error: "URL analysis failed",
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

app.post("/analyze-email", async (req, res) => {
  const { emailContent } = req.body;

  if (!emailContent) {
    return res.status(400).json({ error: "Email content is required" });
  }

  try {
    const metadata = await extractEmailMetadata(emailContent);
    const securityIndicators = await analyzeEmailSecurity(metadata);

    const data = {
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content: `Analyze the following email for spam and phishing indicators.
                   Consider sender reputation, content patterns, and security indicators.
                   Provide a risk assessment percentage and brief explanation in under 50 characters.`
        },
        {
          role: "user",
          content: `Email Metadata: ${JSON.stringify(metadata)}
                   Security Indicators: ${JSON.stringify(securityIndicators)}`
        }
      ]
    };

    const response = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      data,
      {
        headers: {
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        },
        timeout: 10000
      }
    );

    const aiAnalysis = response.data.choices[0].message.content;

    // Store analysis results
    await db.collection("emailAnalysis").insertOne({
      metadata: {
        from: metadata.from,
        subject: metadata.subject,
        date: metadata.date
      },
      securityIndicators,
      aiAnalysis,
      timestamp: new Date(),
      ip: req.ip
    });

    res.json({
      analysis: {
        metadata,
        securityIndicators,
        aiAnalysis,
        riskAssessment: {
          spam: securityIndicators.length > 2 ? "High" : "Low",
          phishing: securityIndicators.length > 3 ? "High" : "Low"
        }
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error("Error analyzing email:", {
      error: error.message,
      timestamp: new Date().toISOString()
    });

    res.status(500).json({
      error: "Email analysis failed",
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    error: "Internal server error",
    timestamp: new Date().toISOString()
  });
});

async function startServer() {
  const client = await connectDB();
  
  app.listen(port, () => {
    console.log(`Security Analysis Server running on port ${port}`);
  });

  process.on('SIGTERM', async () => {
    console.log('Received SIGTERM signal. Shutting down gracefully...');
    await client.close();
    process.exit(0);
  });
}

startServer().catch(console.error);