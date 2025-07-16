// Google Apps Script for logging to Google Sheets
// Deploy this as a Google Apps Script Web App

function doPost(e) {
  try {
    const data = JSON.parse(e.postData.contents);
    
    // Get or create spreadsheet
    const spreadsheet = getOrCreateSpreadsheet();
    const sheet = spreadsheet.getActiveSheet();
    
    // Ensure headers exist
    ensureHeaders(sheet);
    
    // Add data row
    sheet.appendRow([
      data.timestamp,
      data.ip,
      data.country,
      data.userAgent,
      data.action,
      data.score,
      data.reasons.join(', '),
      data.asn,
      data.asOrganization,
      data.url,
      data.method,
      data.processingTime
    ]);
    
    return ContentService.createTextOutput(JSON.stringify({
      success: true,
      message: 'Data logged successfully'
    })).setMimeType(ContentService.MimeType.JSON);
    
  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({
      success: false,
      error: error.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function getOrCreateSpreadsheet() {
  const SPREADSHEET_NAME = 'Anti-Bot Gateway Logs';
  
  // Try to find existing spreadsheet
  const files = DriveApp.getFilesByName(SPREADSHEET_NAME);
  
  if (files.hasNext()) {
    const file = files.next();
    return SpreadsheetApp.openById(file.getId());
  } else {
    // Create new spreadsheet
    return SpreadsheetApp.create(SPREADSHEET_NAME);
  }
}

function ensureHeaders(sheet) {
  const headers = [
    'Timestamp',
    'IP Address',
    'Country',
    'User Agent',
    'Action',
    'Score',
    'Reasons',
    'ASN',
    'AS Organization',
    'URL',
    'Method',
    'Processing Time (ms)'
  ];
  
  // Check if headers exist
  const firstRow = sheet.getRange(1, 1, 1, headers.length).getValues()[0];
  const hasHeaders = firstRow.some(cell => cell !== '');
  
  if (!hasHeaders) {
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    sheet.getRange(1, 1, 1, headers.length).setFontWeight('bold');
  }
}

function getAnalytics() {
  const spreadsheet = getOrCreateSpreadsheet();
  const sheet = spreadsheet.getActiveSheet();
  
  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  const logs = data.slice(1);
  
  // Calculate statistics
  const stats = {
    total: logs.length,
    allowed: logs.filter(row => row[4] === 'ALLOWED').length,
    blocked: logs.filter(row => row[4] === 'BLOCKED').length,
    challenged: logs.filter(row => row[4] === 'TURNSTILE_CHALLENGE').length,
    averageScore: logs.reduce((sum, row) => sum + (row[5] || 0), 0) / logs.length
  };
  
  return stats;
}

// Cleanup function to remove old logs (run periodically)
function cleanupOldLogs() {
  const spreadsheet = getOrCreateSpreadsheet();
  const sheet = spreadsheet.getActiveSheet();
  
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - 30); // Keep 30 days
  
  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  
  // Filter out old logs
  const recentLogs = data.filter((row, index) => {
    if (index === 0) return true; // Keep headers
    const timestamp = new Date(row[0]);
    return timestamp > cutoffDate;
  });
  
  // Clear sheet and write filtered data
  sheet.clear();
  sheet.getRange(1, 1, recentLogs.length, headers.length).setValues(recentLogs);
  sheet.getRange(1, 1, 1, headers.length).setFontWeight('bold');
}