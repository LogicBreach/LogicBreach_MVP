import React, { useState } from 'react';
import axios from 'axios';

function App() {
  const [ip, setIp] = useState('');
  const [results, setResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async () => {
    setError('');
    setIsLoading(true);
    try {
      const response = await axios.post('http://localhost:3001/scan', { ip });
      setResults(response.data);
    } catch (error) {
      setError('Scan failed. Ensure the backend is running!');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ padding: 20, fontFamily: 'Arial', maxWidth: 800, margin: '0 auto' }}>
      <h1 style={{ color: '#2c3e50' }}>🔥 LogicBreach Red Team Simulator</h1>
      
      <div style={{ display: 'flex', marginBottom: 20 }}>
        <input
          type="text"
          placeholder="Enter Target IP (e.g., 127.0.0.1)"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          style={{ padding: 10, marginRight: 10, width: 300, borderRadius: 5, border: '1px solid #ddd' }}
        />
        <button 
          onClick={handleScan}
          disabled={isLoading}
          style={{ 
            padding: '10px 20px', 
            backgroundColor: isLoading ? '#bdc3c7' : '#e74c3c', 
            color: 'white', 
            border: 'none', 
            borderRadius: 5, 
            cursor: 'pointer' 
          }}
        >
          {isLoading ? 'Scanning...' : 'Launch Attack Simulation'}
        </button>
      </div>

      {error && <div style={{ color: '#e74c3c' }}>⚠️ {error}</div>}

      {results && (
        <div style={{ backgroundColor: '#f8f9fa', padding: 20, borderRadius: 10 }}>
          <h2 style={{ color: '#2c3e50' }}>🎯 Target: {results.ip}</h2>
          <h3 style={{ color: '#e74c3c' }}>🚨 Vulnerabilities Found</h3>
          
          {results.vulnerabilities.map((vuln, index) => (
            <div 
              key={index}
              style={{ 
                marginBottom: 15, 
                padding: 15, 
                backgroundColor: '#fff', 
                borderRadius: 5, 
                borderLeft: '4px solid #e74c3c'
              }}
            >
              <h4>{vuln.name}</h4>
              <p><strong>Severity:</strong> {vuln.severity}</p>
              <p><strong>Fix:</strong> {vuln.remediation}</p>
            </div>
          ))}

          <h3 style={{ color: '#2c3e50' }}>🔍 Attack Simulation Report</h3>
          <ul>
            {results.attack_report.map((attack, index) => (
              <li key={index} style={{ margin: '10px 0' }}>💥 {attack}</li>
            ))}
          </ul>

          <h3 style={{ color: '#2c3e50' }}>🤖 AI Threat Analysis</h3>
          <div style={{ padding: 15, backgroundColor: '#fff', borderRadius: 5 }}>
            {results.ai_analysis}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;