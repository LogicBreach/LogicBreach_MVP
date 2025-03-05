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
      const response = await axios.post('http://localhost:3000/scan', { ip });
      setResults(response.data); // Save results to state
    } catch (error) {
      alert('Scan failed! Check the console.');
    }
  };

  return (
    <div style={{ padding: 20 }}>
      <h1>LogicBreach Scanner</h1>
      <input
        type="text"
        placeholder="Enter IP address"
        value={ip}
        onChange={(e) => setIp(e.target.value)}
        style={{ marginRight: 10 }}
      />
      <button onClick={handleScan}>Start Scan</button>

      {/* Display Results */}
      {results.open_ports.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <h2>Results for {results.ip}</h2>
          <p><strong>Open Ports:</strong> {results.open_ports.join(', ')}</p>
          <p><strong>Vulnerabilities:</strong></p>
          <ul>
            {results.vulnerabilities.map((vuln, index) => (
              <li key={index}>{vuln}</li>
            ))}
            {results.vulnerabilities.length === 0 && <li>No vulnerabilities found!</li>}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;