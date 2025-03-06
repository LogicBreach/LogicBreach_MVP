import React, { useState } from 'react';
import axios from 'axios';

function App() {
  const [ip, setIp] = useState('');
  const [results, setResults] = useState({ 
    open_ports: [], 
    vulnerabilities: [] 
  });

  const handleScan = async () => {
    try {
      const response = await axios.post('http://localhost:3001/scan', { ip });
      setResults(response.data);
    } catch (error) {
      alert('Scan failed! Check the console.');
    }
  };

  return (
    <div style={{ padding: 20, fontFamily: 'Arial' }}>
      <h1>🔒 LogicBreach Scanner</h1>
      <input
        type="text"
        placeholder="Enter IP (e.g., 127.0.0.1)"
        value={ip}
        onChange={(e) => setIp(e.target.value)}
        style={{ padding: 10, marginRight: 10, width: 300 }}
      />
      <button 
        onClick={handleScan}
        style={{ padding: 10, backgroundColor: '#4CAF50', color: 'white', border: 'none' }}
      >
        Start Scan
      </button>

      {results.open_ports.length > 0 && (
        <div style={{ marginTop: 20, backgroundColor: '#f0f0f0', padding: 20, borderRadius: 10 }}>
          <h2>📋 Results for {results.ip}</h2>
          <p><strong>Open Ports:</strong> {results.open_ports.join(', ')}</p>
          <p><strong>🚨 Vulnerabilities:</strong></p>
          <ul>
            {results.vulnerabilities.map((vuln, index) => (
              <li key={index} style={{ color: 'red' }}>{vuln}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;