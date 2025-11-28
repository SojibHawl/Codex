# 🔒 Text Redaction Tool

A simple web-based tool that helps you find and remove sensitive information from text!

## What does it do?

This tool can detect and redact these types of sensitive data:
- **PERSON** - Names of people (like John Smith)
- **LOCATION** - Places and addresses (like New York, California)
- **EMAIL_ADDRESS** - Email addresses (like john@gmail.com)
- **IP_ADDRESS** - IP addresses (like 192.168.1.1)
- **PHONE_NUMBER** - Phone numbers (like (212) 555-1234)
- **CREDIT_CARD** - Credit card numbers
- **DATE_TIME** - Dates in various formats
- **URL** - Website links

## How to use it?

1. Open `index.html` in your web browser (just double click it!)
2. Choose your mode:
   - **Redact Mode**: Completely removes sensitive info
   - **Mask Mode**: Replaces with [ENTITY_TYPE] labels
3. Type or paste your text in the text box
4. Or upload a `.txt` file
5. Click the "🚀 Redact Text" button
6. See the results!

## What you'll see

- **Original Text**: Your input text
- **Redacted Text**: Text with sensitive info removed/masked
- **Accuracy Score**: Shows how much was changed (Levenshtein similarity)
- **Entity Table**: List of all detected entities with their positions
- **Summary Stats**: Quick count of different entity types

## Example

**Input:**
```
John Smith's phone number is (212) 555-1234 and his email is john@gmail.com. He lives in New York.
```

**Output (Redact Mode):**
```
's phone number is  and his email is . He lives in .
```

**Output (Mask Mode):**
```
[PERSON]'s phone number is [PHONE_NUMBER] and his email is [EMAIL_ADDRESS]. He lives in [LOCATION].
```

## Files in this project

- `index.html` - The main webpage
- `style.css` - Makes everything look nice
- `script.js` - The brain of the tool (does all the work)
- `README.md` - This file you're reading!
- `test_input.txt` - Sample text to test the tool

## How it works (simple explanation)

1. We use **Regular Expressions (regex)** to find patterns like emails, phone numbers, etc.
2. For names and locations, we have lists of common ones and look for them
3. We keep track of where each entity is found (start and end position)
4. Then we replace or remove them based on your chosen mode
5. We calculate similarity using the **Levenshtein Distance** algorithm

## Tech used

- HTML (for the page structure)
- CSS (for styling)
- JavaScript (for the logic)
- No external libraries needed! Just open and use.

## Setup

No installation needed! Just:
1. Download all files
2. Open `index.html` in any browser
3. Start redacting!

## Notes

- This is a simple rule-based system
- It might not catch everything (no AI is 100% perfect!)
- Works best with English text
- All processing happens in your browser - nothing is sent anywhere!

---
Made for Cybersecurity Hackathon 🎯
