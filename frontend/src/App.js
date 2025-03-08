import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import { FiServer, FiAlertTriangle, FiClock, FiShield, FiDownload } from 'react-icons/fi';

const COLORS = ['#e74c3c', '#f39c12', '#2ecc71', '#3498db'];

function App() {
  const [ip, setIp] = useState('');
  const [results, setResults] = useState(null);
  const [history, setHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [stats, setStats] = useState({ totalScans: 0, criticalVulns: 0 });
  const [error, setError] = useState('');

  const fetchHistory = async (ip) => {
    try {
      const response = await axios.get(`http://localhost:3001/history/${ip}`);
      setHistory(response.data);
    } catch (error) {
      console.error("Failed to fetch history");
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get('http://localhost:3001/stats');
      setStats(response.data);
    } catch (error) {
      console.error("Failed to fetch stats");
    }
  };

  const handleScan = async () => {
    setError('');
    setResults(null);
    setIsLoading(true);
    try {
      const response = await axios.post('http://localhost:3001/scan', { ip });
      setResults(response.data);
      fetchHistory(ip);
      fetchStats();
    } catch (error) {
      setError(error.response?.data?.error || 'Scan failed. Check backend connection.');
    } finally {
      setIsLoading(false);
    }
  };

  const severityData = results?.vulnerabilities?.reduce((acc, vuln) => {
    acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', padding: 20, fontFamily: 'Arial' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 40, padding: 20, backgroundColor: '#fff', borderRadius: 10 }}>
        <FiShield size={40} color="#3498db" style={{ marginRight: 15 }} />
        <h1 style={{ color: '#2c3e50', margin: 0 }}>LogicBreach Security Platform</h1>
      </div>

      {/* Stats Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 20, marginBottom: 40 }}>
        <div style={{ backgroundColor: '#fff', padding: 20, borderRadius: 10, boxShadow: '0 2px 4px rgba(0,0,0,0.1)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <FiServer size={24} color="#3498db" />
            <h3 style={{ margin: 0 }}>Total Scans</h3>
          </div>
          <p style={{ fontSize: 32, fontWeight: 'bold', margin: '10px 0' }}>{stats.totalScans}</p>
        </div>
        
        <div style={{ backgroundColor: '#fff', padding: 20, borderRadius: 10, boxShadow: '0 2px 4px rgba(0,0,0,0.1)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <FiAlertTriangle size={24} color="#e74c3c" />
            <h3 style={{ margin: 0 }}>Critical Risks Found</h3>
          </div>
          <p style={{ fontSize: 32, fontWeight: 'bold', margin: '10px 0' }}>{stats.criticalVulns}</p>
        </div>
      </div>

      {/* Scan Input */}
      <div style={{ backgroundColor: '#fff', padding: 20, borderRadius: 10, marginBottom: 40, boxShadow: '0 2px 4px rgba(0,0,0,0.1)' }}>
        <div style={{ display: 'flex', gap: 15, alignItems: 'center' }}>
          <input
            type="text"
            placeholder="Enter IP/Domain (e.g., 192.168.1.1)"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            style={{ 
              flex: 1, 
              padding: 12, 
              border: '1px solid #ddd', 
              borderRadius: 5,
              fontSize: 16
            }}
          />
          <button 
            onClick={handleScan}
            disabled={isLoading}
            style={{ 
              padding: '12px 25px',
              backgroundColor: isLoading ? '#bdc3c7' : '#3498db',
              color: 'white',
              border: 'none',
              borderRadius: 5,
              cursor: 'pointer',
              fontSize: 16,
              display: 'flex',
              alignItems: 'center',
              gap: 10
            }}
          >
            {isLoading ? 'Scanning...' : 'Run Security Audit'}
          </button>
        </div>
        {error && <div style={{ color: '#e74c3c', marginTop: 10 }}>⚠️ {error}</div>}
      </div>

      {/* Results Section */}
      {results && (
        <div style={{ backgroundColor: '#fff', padding: 20, borderRadius: 10, boxShadow: '0 2px 4px rgba(0,0,0,0.1)' }}>
          {/* Report Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 30 }}>
            <h2 style={{ color: '#2c3e50', margin: 0 }}>
              🎯 Target: {results.ip} 
              <span style={{ fontSize: 14, color: '#7f8c8d', marginLeft: 10 }}>
                {new Date(results.timestamp).toLocaleString()}
              </span>
            </h2>
            <a 
              href={`http://localhost:3001/report/${results.ip}`} 
              target="_blank" 
              rel="noopener noreferrer"
              style={{
                padding: '10px 20px',
                backgroundColor: '#27ae60',
                color: 'white',
                borderRadius: 5,
                textDecoration: 'none',
                display: 'flex',
                alignItems: 'center',
                gap: 8
              }}
            >
              <FiDownload /> PDF Report
            </a>
          </div>

          {/* Charts */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 40, marginBottom: 40 }}>
            {/* Vulnerability Trend */}
            <div>
              <h3 style={{ color: '#2c3e50' }}><FiClock style={{ marginRight: 10 }} />Security Health Over Time</h3>
              <LineChart width={500} height={300} data={history}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="timestamp" />
                <YAxis />
                <Tooltip />
                <Line 
                  type="monotone" 
                  dataKey="data.vulnerabilities.length" 
                  stroke="#e74c3c" 
                  strokeWidth={2}
                />
              </LineChart>
            </div>

            {/* Severity Distribution */}
            <div>
              <h3 style={{ color: '#2c3e50' }}><FiAlertTriangle style={{ marginRight: 10 }} />Risk Severity Breakdown</h3>
              <PieChart width={500} height={300}>
                <Pie
                  data={Object.entries(severityData || {}).map(([severity, count]) => ({
                    name: `${severity}/10 Severity`,
                    value: count
                  }))}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  label
                >
                  {Object.keys(severityData || {}).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </div>
          </div>

          {/* Vulnerability List */}
          <div>
            <h3 style={{ color: '#2c3e50', marginBottom: 20 }}>🔍 Detailed Findings</h3>
            {results.vulnerabilities.length > 0 ? (
              results.vulnerabilities.map((vuln, index) => (
                <div 
                  key={index}
                  style={{ 
                    marginBottom: 15,
                    padding: 20,
                    borderLeft: `4px solid ${vuln.severity >= 8 ? '#e74c3c' : '#f39c12'}`,
                    backgroundColor: '#f8f9fa',
                    borderRadius: 5
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <h4 style={{ margin: 0, color: '#2c3e50' }}>{vuln.name}</h4>
                      <p style={{ margin: '5px 0', color: '#7f8c8d' }}>{vuln.cve}</p>
                    </div>
                    <div style={{ 
                      backgroundColor: vuln.severity >= 8 ? '#e74c3c' : '#f39c12',
                      color: 'white',
                      padding: '5px 15px',
                      borderRadius: 3,
                      fontSize: 14
                    }}>
                      Severity {vuln.severity}/10
                    </div>
                  </div>
                  <div style={{ marginTop: 15 }}>
                    <p style={{ margin: '8px 0' }}>
                      <strong>Recommended Fix:</strong><br/>
                      {vuln.remediation}
                    </p>
                    <p style={{ color: '#e74c3c', margin: '8px 0' }}>
                      <FiAlertTriangle style={{ verticalAlign: 'middle', marginRight: 5 }} />
                      {vuln.attack_simulation}
                    </p>
                  </div>
                </div>
              ))
            ) : (
              <div style={{ 
                padding: 20, 
                backgroundColor: '#f8f9fa', 
                borderRadius: 5,
                textAlign: 'center',
                color: '#27ae60'
              }}>
                ✅ No security vulnerabilities detected
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;