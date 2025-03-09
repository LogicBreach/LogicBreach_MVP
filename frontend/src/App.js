import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip } from 'recharts';
import { FiAlertTriangle, FiDownload, FiClock, FiUser, FiLock } from 'react-icons/fi';

const COLORS = ['#e74c3c', '#f39c12', '#2ecc71', '#3498db'];
const DARK_THEME = {
  background: '#1a1a1a',
  text: '#ffffff',
  cardBackground: '#2d2d2d',
  border: '#404040',
  primary: '#3498db',
  danger: '#e74c3c',
  success: '#2ecc71'
};

export default function App() {
  const [target, setTarget] = useState('');
  const [duration, setDuration] = useState(5);
  const [results, setResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authMode, setAuthMode] = useState('login');

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) setIsAuthenticated(true);
  }, []);

  const handleAuth = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const endpoint = authMode === 'login' ? '/login' : '/register';
      const response = await axios.post(`http://localhost:3001${endpoint}`, {
        email, password
      });

      if (authMode === 'login') {
        localStorage.setItem('token', response.data.access_token);
        setIsAuthenticated(true);
      } else {
        setAuthMode('login');
        setError('Registration successful. Please login.');
      }
    } catch (err) {
      setError(err.response?.data?.msg || 'Authentication failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setIsAuthenticated(false);
    setResults(null);
  };

  const handleScan = async () => {
    setError('');
    setIsLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post('http://localhost:3001/scan', {
        target,
        duration
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setResults(response.data);
    } catch (error) {
      setError('Scan failed. Check target format or login status.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownloadReport = async () => {
    try {
      const response = await axios.post('http://localhost:3001/report', results);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `logicbreach_report_${target}.pdf`);
      document.body.appendChild(link);
      link.click();
    } catch (error) {
      setError('Failed to generate report');
    }
  };

  const severityData = results?.results?.reduce((acc, result) => {
    result.vulnerabilities.forEach(vuln => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    });
    return acc;
  }, {});

  if (!isAuthenticated) {
    return (
      <div style={{ 
        maxWidth: 500, 
        margin: '50px auto', 
        padding: 20, 
        fontFamily: 'Arial',
        backgroundColor: DARK_THEME.background,
        minHeight: '100vh'
      }}>
        <h1 style={{ 
          color: DARK_THEME.text, 
          textAlign: 'center',
          marginBottom: '2rem'
        }}>
          🔐 LogicBreach
        </h1>

        <form onSubmit={handleAuth} style={{ 
          backgroundColor: DARK_THEME.cardBackground,
          padding: 30,
          borderRadius: 10,
          display: 'flex',
          flexDirection: 'column',
          gap: 15
        }}>
          <div style={{ position: 'relative' }}>
            <FiUser style={{ 
              position: 'absolute', 
              left: 10, 
              top: 12,
              color: DARK_THEME.text 
            }} />
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={{ 
                padding: '10px 10px 10px 35px', 
                width: '100%',
                background: DARK_THEME.cardBackground,
                border: `1px solid ${DARK_THEME.border}`,
                color: DARK_THEME.text
              }}
              required
            />
          </div>

          <div style={{ position: 'relative' }}>
            <FiLock style={{ 
              position: 'absolute', 
              left: 10, 
              top: 12,
              color: DARK_THEME.text 
            }} />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{ 
                padding: '10px 10px 10px 35px', 
                width: '100%',
                background: DARK_THEME.cardBackground,
                border: `1px solid ${DARK_THEME.border}`,
                color: DARK_THEME.text
              }}
              required
            />
          </div>

          {error && <div style={{ 
            color: DARK_THEME.danger, 
            textAlign: 'center',
            padding: '10px',
            borderRadius: '5px',
            backgroundColor: '#e74c3c20'
          }}>
            {error}
          </div>}

          <button
            type="submit"
            disabled={isLoading}
            style={{
              padding: 15,
              backgroundColor: isLoading ? DARK_THEME.border : DARK_THEME.primary,
              color: 'white',
              border: 'none',
              borderRadius: 5,
              cursor: 'pointer',
              fontWeight: 'bold'
            }}
          >
            {isLoading ? 'Processing...' : authMode === 'login' ? 'Login' : 'Register'}
          </button>

          <p style={{ 
            textAlign: 'center', 
            marginTop: 15,
            color: DARK_THEME.text 
          }}>
            {authMode === 'login' 
              ? "Don't have an account? "
              : "Already have an account? "}
            <button
              type="button"
              onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')}
              style={{
                background: 'none',
                border: 'none',
                color: DARK_THEME.primary,
                cursor: 'pointer',
                textDecoration: 'underline'
              }}
            >
              {authMode === 'login' ? 'Register here' : 'Login here'}
            </button>
          </p>
        </form>
      </div>
    );
  }

  return (
    <div style={{ 
      maxWidth: 1200, 
      margin: '0 auto', 
      padding: 20, 
      fontFamily: 'Arial',
      backgroundColor: DARK_THEME.background,
      minHeight: '100vh',
      color: DARK_THEME.text
    }}>
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between',
        marginBottom: '2rem'
      }}>
        <h1 style={{ 
          color: DARK_THEME.text, 
          borderBottom: `2px solid ${DARK_THEME.primary}`, 
          paddingBottom: 10 
        }}>
          🔥 LogicBreach
        </h1>
        <button
          onClick={handleLogout}
          style={{
            padding: '10px 20px',
            backgroundColor: DARK_THEME.danger,
            color: 'white',
            border: 'none',
            borderRadius: 5,
            cursor: 'pointer'
          }}
        >
          Logout
        </button>
      </div>

      <div style={{ 
        backgroundColor: DARK_THEME.cardBackground,
        padding: 20, 
        borderRadius: 10, 
        marginBottom: 20,
        display: 'grid',
        gridTemplateColumns: '1fr 1fr auto',
        gap: 15
      }}>
        <input
          type="text"
          placeholder="Domain/IP Range (e.g., 192.168.1.1-10)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          style={{ 
            padding: 10, 
            borderRadius: 5, 
            border: `1px solid ${DARK_THEME.border}`,
            backgroundColor: DARK_THEME.cardBackground,
            color: DARK_THEME.text
          }}
        />
        <input
          type="number"
          placeholder="Duration (minutes)"
          value={duration}
          onChange={(e) => setDuration(e.target.value)}
          style={{ 
            padding: 10, 
            borderRadius: 5, 
            border: `1px solid ${DARK_THEME.border}`,
            backgroundColor: DARK_THEME.cardBackground,
            color: DARK_THEME.text
          }}
        />
        <button
          onClick={handleScan}
          disabled={isLoading}
          style={{
            padding: '10px 20px',
            backgroundColor: isLoading ? DARK_THEME.border : DARK_THEME.primary,
            color: 'white',
            border: 'none',
            borderRadius: 5,
            cursor: 'pointer'
          }}
        >
          {isLoading ? <><FiClock /> Scanning...</> : 'Launch Attack'}
        </button>
      </div>

      {error && <div style={{ 
        color: DARK_THEME.danger, 
        padding: 10,
        backgroundColor: '#e74c3c20',
        borderRadius: 5
      }}>
        {error}
      </div>}

      {results && (
        <div style={{ 
          backgroundColor: DARK_THEME.cardBackground, 
          padding: 20, 
          borderRadius: 10 
        }}>
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            marginBottom: 20 
          }}>
            <h2 style={{ color: DARK_THEME.text }}>
              🎯 Target: {results.target} 
              <span style={{ 
                fontSize: 14, 
                color: '#7f8c8d', 
                marginLeft: 10 
              }}>
                ({results.results.length} hosts scanned)
              </span>
            </h2>
            <button
              onClick={handleDownloadReport}
              style={{
                padding: '10px 20px',
                backgroundColor: DARK_THEME.success,
                color: 'white',
                border: 'none',
                borderRadius: 5,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8
              }}
            >
              <FiDownload /> Download Report
            </button>
          </div>

          <div style={{ marginBottom: 30 }}>
            <h3 style={{ color: DARK_THEME.text }}><FiAlertTriangle /> Risk Severity</h3>
            <PieChart width={500} height={300}>
              <Pie
                data={Object.entries(severityData || {}).map(([severity, count]) => ({
                  name: `${severity}/10`,
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
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: DARK_THEME.cardBackground,
                  border: 'none',
                  borderRadius: 5
                }}
                itemStyle={{ color: DARK_THEME.text }}
              />
            </PieChart>
          </div>

          {results.results.map((result, index) => (
            <div key={index} style={{ 
              marginBottom: 15,
              padding: 15,
              borderLeft: `4px solid ${result.vulnerabilities.length ? DARK_THEME.danger : DARK_THEME.success}`,
              backgroundColor: DARK_THEME.background,
              borderRadius: 5
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <div>
                  <h4 style={{ margin: 0, color: DARK_THEME.text }}>{result.ip}</h4>
                  <p style={{ 
                    margin: '5px 0', 
                    color: '#7f8c8d' 
                  }}>
                    Open Ports: {result.open_ports.join(', ')}
                  </p>
                </div>
                <div style={{ 
                  backgroundColor: result.vulnerabilities.length ? DARK_THEME.danger : DARK_THEME.success,
                  color: 'white',
                  padding: '5px 15px',
                  borderRadius: 3
                }}>
                  {result.vulnerabilities.length} Risks
                </div>
              </div>
              {result.vulnerabilities.map((vuln, vulnIndex) => (
                <div key={vulnIndex} style={{ 
                  marginTop: 10, 
                  padding: 10, 
                  backgroundColor: DARK_THEME.cardBackground,
                  borderRadius: 5
                }}>
                  <p style={{ 
                    margin: 0, 
                    fontWeight: 'bold',
                    color: DARK_THEME.text 
                  }}>{vuln.name}</p>
                  <p style={{ 
                    margin: '5px 0',
                    color: DARK_THEME.text 
                  }}>{vuln.remediation}</p>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}