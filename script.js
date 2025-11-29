// ========================================
// TEXT REDACTION TOOL - Main JavaScript
// ========================================

// This array will store all the entities we find
let detectedEntities = [];

// ========================================
// REGEX PATTERNS - These help us find sensitive info
// ========================================

// Pattern for email addresses like john@gmail.com
const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

// Pattern for phone numbers (different formats)
const phonePattern = /(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;

// Pattern for IP addresses like 192.168.1.1
const ipPattern = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;

// Pattern for credit card numbers (16 digits with optional spaces/dashes)
const creditCardPattern = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g;

// Pattern for URLs like http://example.com or www.example.com
const urlPattern = /(https?:\/\/[^\s]+)|(www\.[^\s]+)/g;

// Pattern for dates (different formats)
const datePattern = /\b(\d{1,2}[-\/]\d{1,2}[-\/]\d{2,4})|(\d{4}[-\/]\d{1,2}[-\/]\d{1,2})|((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s,]+\d{1,2}[\s,]+\d{4})|(\d{1,2}[\s]+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s,]+\d{4})\b/gi;

// Common names list for person detection (simple approach)
const commonNames = [
    'james', 'john', 'robert', 'michael', 'william', 'david', 'richard', 'joseph', 'thomas', 'charles',
    'mary', 'patricia', 'jennifer', 'linda', 'elizabeth', 'barbara', 'susan', 'jessica', 'sarah', 'karen',
    'smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller', 'davis', 'rodriguez', 'martinez',
    'alex', 'chris', 'taylor', 'jordan', 'casey', 'morgan', 'jamie', 'drew', 'sam', 'pat',
    'emma', 'olivia', 'ava', 'sophia', 'isabella', 'mia', 'charlotte', 'amelia', 'harper', 'evelyn',
    'liam', 'noah', 'oliver', 'elijah', 'lucas', 'mason', 'logan', 'alexander', 'ethan', 'jacob',
    'daniel', 'matthew', 'henry', 'sebastian', 'jack', 'aiden', 'owen', 'samuel', 'ryan', 'nathan',
    'alice', 'anna', 'emily', 'grace', 'lily', 'chloe', 'zoe', 'hannah', 'natalie', 'victoria',
    'mr', 'mrs', 'ms', 'dr', 'prof'
];

// Common locations list
const commonLocations = [
    'new york', 'Bangladesh', 'los angeles', 'chicago', 'houston', 'phoenix', 'philadelphia', 'san antonio', 'san diego',
    'dallas', 'san jose', 'austin', 'jacksonville', 'fort worth', 'columbus', 'charlotte', 'seattle',
    'denver', 'boston', 'detroit', 'nashville', 'portland', 'las vegas', 'baltimore', 'louisville',
    'milwaukee', 'albuquerque', 'tucson', 'fresno', 'sacramento', 'atlanta', 'miami', 'oakland',
    'london', 'paris', 'tokyo', 'sydney', 'toronto', 'berlin', 'madrid', 'rome', 'amsterdam', 'dubai',
    'california', 'texas', 'florida', 'new jersey', 'illinois', 'pennsylvania', 'ohio', 'georgia',
    'north carolina', 'michigan', 'usa', 'uk', 'canada', 'australia', 'germany', 'france', 'japan',
    'india', 'china', 'brazil', 'mexico', 'spain', 'italy', 'russia', 'south korea', 'netherlands',
    'street', 'avenue', 'road', 'boulevard', 'drive', 'lane', 'court', 'place', 'way', 'circle'
];

// ========================================
// MAIN FUNCTION - Process the text
// ========================================

function processText() {
    // Get the input text
    let inputText = document.getElementById('inputText').value;
    
    // Check if there's any text
    if (inputText.trim() === '') {
        alert('Please enter some text first!');
        return;
    }
    
    // Clear previous results
    detectedEntities = [];
    
    // Get the selected mode (redact or mask)
    let mode = document.querySelector('input[name="mode"]:checked').value;
    
    // Show original text
    document.getElementById('originalOutput').textContent = inputText;
    
    // Find all entities
    findAllEntities(inputText);
    
    // Sort entities by start index (important for replacement)
    detectedEntities.sort((a, b) => b.startIndex - a.startIndex);
    
    // Create redacted version
    let redactedText = inputText;
    
    // Replace each entity based on mode
    for (let entity of detectedEntities) {
        let replacement;
        if (mode === 'mask') {
            replacement = '[' + entity.type + ']';
        } else {
            replacement = ''; // just remove it
        }
        
        // Replace the text
        redactedText = redactedText.substring(0, entity.startIndex) + 
                       replacement + 
                       redactedText.substring(entity.endIndex);
    }
    
    // Show redacted text
    document.getElementById('redactedOutput').textContent = redactedText;
    
    // Calculate accuracy
    let similarity = calculateLevenshteinSimilarity(inputText, redactedText);
    document.getElementById('accuracyScore').textContent = similarity.toFixed(1) + '%';
    
    // Update the entity table
    updateEntityTable();
    
    // Update stats
    updateStats();
}

// ========================================
// FIND ALL ENTITIES
// ========================================

function findAllEntities(text) {
    // Find emails
    findWithRegex(text, emailPattern, 'EMAIL_ADDRESS');
    
    // Find phone numbers
    findWithRegex(text, phonePattern, 'PHONE_NUMBER');
    
    // Find IP addresses
    findWithRegex(text, ipPattern, 'IP_ADDRESS');
    
    // Find credit cards
    findWithRegex(text, creditCardPattern, 'CREDIT_CARD');
    
    // Find URLs
    findWithRegex(text, urlPattern, 'URL');
    
    // Find dates
    findWithRegex(text, datePattern, 'DATE_TIME');
    
    // Find persons (using our simple method)
    findPersons(text);
    
    // Find locations
    findLocations(text);
    
    // Remove duplicates and overlaps
    removeDuplicates();
}

// Helper function to find matches using regex
function findWithRegex(text, pattern, entityType) {
    // Reset the regex
    pattern.lastIndex = 0;
    
    let match;
    while ((match = pattern.exec(text)) !== null) {
        detectedEntities.push({
            type: entityType,
            text: match[0],
            startIndex: match.index,
            endIndex: match.index + match[0].length
        });
    }
}

// Find person names (simple approach - looks for capitalized words)
function findPersons(text) {
    // Pattern to find capitalized words that might be names
    let words = text.split(/\s+/);
    let currentIndex = 0;
    
    for (let i = 0; i < words.length; i++) {
        let word = words[i];
        let cleanWord = word.replace(/[^a-zA-Z]/g, '').toLowerCase();
        
        // Find the actual position in text
        let wordStart = text.indexOf(word, currentIndex);
        if (wordStart === -1) continue;
        
        currentIndex = wordStart + word.length;
        
        // Check if it's a name (starts with capital and in our list)
        if (word[0] && word[0] === word[0].toUpperCase() && word[0] !== word[0].toLowerCase()) {
            if (commonNames.includes(cleanWord)) {
                // Check if next word is also a name (for full names like "John Smith")
                let fullName = word;
                let endIndex = wordStart + word.length;
                
                if (i + 1 < words.length) {
                    let nextWord = words[i + 1];
                    let nextClean = nextWord.replace(/[^a-zA-Z]/g, '').toLowerCase();
                    
                    if (nextWord[0] && nextWord[0] === nextWord[0].toUpperCase() && 
                        (commonNames.includes(nextClean) || nextWord.length > 2)) {
                        let nextStart = text.indexOf(nextWord, endIndex);
                        if (nextStart !== -1 && nextStart - endIndex <= 2) {
                            fullName = text.substring(wordStart, nextStart + nextWord.length);
                            endIndex = nextStart + nextWord.length;
                            i++; // skip next word
                        }
                    }
                }
                
                detectedEntities.push({
                    type: 'PERSON',
                    text: fullName,
                    startIndex: wordStart,
                    endIndex: endIndex
                });
            }
        }
    }
}

// Find locations
function findLocations(text) {
    let lowerText = text.toLowerCase();
    
    for (let location of commonLocations) {
        let searchIndex = 0;
        let foundIndex;
        
        while ((foundIndex = lowerText.indexOf(location, searchIndex)) !== -1) {
            // Check if it's a whole word (not part of another word)
            let before = foundIndex > 0 ? lowerText[foundIndex - 1] : ' ';
            let after = foundIndex + location.length < lowerText.length ? 
                        lowerText[foundIndex + location.length] : ' ';
            
            if (!/[a-z]/.test(before) && !/[a-z]/.test(after)) {
                // Get the original case version
                let originalText = text.substring(foundIndex, foundIndex + location.length);
                
                detectedEntities.push({
                    type: 'LOCATION',
                    text: originalText,
                    startIndex: foundIndex,
                    endIndex: foundIndex + location.length
                });
            }
            
            searchIndex = foundIndex + 1;
        }
    }
}

// Remove duplicate and overlapping entities
function removeDuplicates() {
    // Sort by start index
    detectedEntities.sort((a, b) => a.startIndex - b.startIndex);
    
    let filtered = [];
    let lastEnd = -1;
    
    for (let entity of detectedEntities) {
        // Skip if this entity overlaps with previous one
        if (entity.startIndex >= lastEnd) {
            filtered.push(entity);
            lastEnd = entity.endIndex;
        }
    }
    
    detectedEntities = filtered;
}

// ========================================
// LEVENSHTEIN DISTANCE CALCULATION
// ========================================

function calculateLevenshteinDistance(str1, str2) {
    // Create a matrix
    let matrix = [];
    
    // Fill first column
    for (let i = 0; i <= str1.length; i++) {
        matrix[i] = [i];
    }
    
    // Fill first row
    for (let j = 0; j <= str2.length; j++) {
        matrix[0][j] = j;
    }
    
    // Fill the rest of the matrix
    for (let i = 1; i <= str1.length; i++) {
        for (let j = 1; j <= str2.length; j++) {
            if (str1[i - 1] === str2[j - 1]) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1, // substitution
                    matrix[i][j - 1] + 1,     // insertion
                    matrix[i - 1][j] + 1      // deletion
                );
            }
        }
    }
    
    return matrix[str1.length][str2.length];
}

function calculateLevenshteinSimilarity(str1, str2) {
    let distance = calculateLevenshteinDistance(str1, str2);
    let maxLength = Math.max(str1.length, str2.length);
    
    if (maxLength === 0) return 100;
    
    let similarity = ((maxLength - distance) / maxLength) * 100;
    return similarity;
}

// ========================================
// UPDATE THE UI
// ========================================

function updateEntityTable() {
    let tableBody = document.getElementById('entityTableBody');
    let table = document.getElementById('entityTable');
    let noEntitiesMsg = document.getElementById('noEntities');
    
    // Clear the table
    tableBody.innerHTML = '';
    
    if (detectedEntities.length === 0) {
        table.style.display = 'none';
        noEntitiesMsg.style.display = 'block';
        return;
    }
    
    table.style.display = 'table';
    noEntitiesMsg.style.display = 'none';
    
    // Sort by start index for display
    let sortedEntities = [...detectedEntities].sort((a, b) => a.startIndex - b.startIndex);
    
    // Add each entity to the table
    for (let entity of sortedEntities) {
        let row = document.createElement('tr');
        
        row.innerHTML = `
            <td><span class="entity-type">${entity.type}</span></td>
            <td>${escapeHtml(entity.text)}</td>
            <td>${entity.startIndex}</td>
            <td>${entity.endIndex}</td>
        `;
        
        tableBody.appendChild(row);
    }
}

function updateStats() {
    // Count total entities
    document.getElementById('totalEntities').textContent = detectedEntities.length;
    
    // Count by type
    let personCount = detectedEntities.filter(e => e.type === 'PERSON').length;
    let emailCount = detectedEntities.filter(e => e.type === 'EMAIL_ADDRESS').length;
    let phoneCount = detectedEntities.filter(e => e.type === 'PHONE_NUMBER').length;
    
    document.getElementById('personCount').textContent = personCount;
    document.getElementById('emailCount').textContent = emailCount;
    document.getElementById('phoneCount').textContent = phoneCount;
}

// Helper function to escape HTML
function escapeHtml(text) {
    let div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ========================================
// CLEAR ALL
// ========================================

function clearAll() {
    document.getElementById('inputText').value = '';
    document.getElementById('originalOutput').textContent = '';
    document.getElementById('redactedOutput').textContent = '';
    document.getElementById('accuracyScore').textContent = '--%';
    document.getElementById('entityTableBody').innerHTML = '';
    document.getElementById('entityTable').style.display = 'none';
    document.getElementById('noEntities').style.display = 'block';
    document.getElementById('totalEntities').textContent = '0';
    document.getElementById('personCount').textContent = '0';
    document.getElementById('emailCount').textContent = '0';
    document.getElementById('phoneCount').textContent = '0';
    document.getElementById('fileInput').value = '';
    
    detectedEntities = [];
}

// ========================================
// FILE UPLOAD HANDLING
// ========================================

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('fileInput').addEventListener('change', function(event) {
        let file = event.target.files[0];
        
        if (file) {
            let reader = new FileReader();
            
            reader.onload = function(e) {
                document.getElementById('inputText').value = e.target.result;
            };
            
            reader.onerror = function() {
                alert('Error reading file!');
            };
            
            reader.readAsText(file);
        }
    });
});
