import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import { FiAlertTriangle, FiDownload, FiClock, FiShield, FiServer, FiLink, FiCheckCircle } from 'react-icons/fi';

const COLORS = ['#e74c3c', '#f39c12', '#2ecc71', '#3498db'];
const DARK_THEME = {
  background: '#0a0a0a',
  text: '#ffffff',
  cardBackground: '#1a1a1a',
  border: '#333333',
  primary: '#3498db',
  danger: '#e74c3c',
  success: '#2ecc71',
  warning: '#f1c40f'
};

const MITRE_TACTICS = {
  'TA0001': 'Initial Access',
  'TA0002': 'Execution',
  'TA0003': 'Persistence',
  'TA0004': 'Privilege Escalation',
  'TA0005': 'Defense Evasion'
};

export default function App() {
  const [target, setTarget] = useState('');
  const [duration, setDuration] = useState(5);
  const [results, setResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [scanId, setScanId] = useState('');
  const [progress, setProgress] = useState(0);
  const [attackGraph, setAttackGraph] = useState(null);
  const [compliance, setCompliance] = useState({});
  const [executiveSummary, setExecutiveSummary] = useState(null);

  useEffect(() => {
    if (scanId) {
      const interval = setInterval(async () => {
        try {
          const response = await axios.get(`http://localhost:3001/scan-status/${scanId}`);
          if (response.data.status === 'completed') {
            setResults(response.data.results);
            setAttackGraph(response.data.attack_graph);
            setCompliance(response.data.compliance);
            setExecutiveSummary({
              totalHosts: response.data.results.length,
              criticalVulns: response.data.results.reduce((acc, host) => 
                acc + host.vulnerabilities.filter(v => v.severity >= 9).length, 0),
              exploitSuccess: response.data.results.filter(h => h.exploit).length
            });
            setScanId('');
            setIsLoading(false);
          }
          setProgress(response.data.progress || 0);
        } catch (err) {
          console.error(err);
        }
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [scanId]);

  const handleScan = async () => {
    setError('');
    setIsLoading(true);
    try {
      const response = await axios.post('http://localhost:3001/scan', {
        target,
        duration
      });
      setScanId(response.data.scan_id);
    } catch (error) {
      setError('Scan failed. Check target format.');
      setIsLoading(false);
    }
  };

  const handleDownloadReport = async () => {
    try {
      const reportData = {
        target,
        results,
        compliance,
        attackGraph
      };
      const response = await axios.post('http://localhost:3001/report', reportData);
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

  const severityData = results?.reduce((acc, result) => {
    result.vulnerabilities.forEach(vuln => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    });
    return acc;
  }, {});

  return (
    <div style={{ 
      maxWidth: 1400, 
      margin: '0 auto', 
      padding: 20, 
      fontFamily: 'Arial',
      backgroundColor: DARK_THEME.background,
      minHeight: '100vh',
      color: DARK_THEME.text
    }}>
      <header style={{ 
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 30,
        paddingBottom: 20,
        borderBottom: `2px solid ${DARK_THEME.primary}`
      }}>
        <h1 style={{ margin: 0 }}>
          <span style={{ color: DARK_THEME.primary }}>⚡</span> 
          LogicBreach Enterprise
        </h1>
        <div style={{ display: 'flex', gap: 15 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <FiShield style={{ color: DARK_THEME.success }} />
            <span>v2.1</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <FiServer />
            <span>Production</span>
          </div>
        </div>
      </header>

      {/* Scan Controls */}
      <div style={{ 
        backgroundColor: DARK_THEME.cardBackground,
        padding: 20, 
        borderRadius: 10, 
        marginBottom: 20,
        display: 'grid',
        gridTemplateColumns: '1fr 1fr auto',
        gap: 15,
        boxShadow: '0 4px 6px rgba(0,0,0,0.2)'
      }}>
        <input
          type="text"
          placeholder="Domain/IP Range (e.g., 192.168.1.1-10)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          style={{ 
            padding: 12, 
            borderRadius: 6, 
            border: `1px solid ${DARK_THEME.border}`,
            backgroundColor: DARK_THEME.cardBackground,
            color: DARK_THEME.text,
            fontSize: 14
          }}
        />
        <input
          type="number"
          placeholder="Duration (minutes)"
          value={duration}
          onChange={(e) => setDuration(e.target.value)}
          style={{ 
            padding: 12, 
            borderRadius: 6, 
            border: `1px solid ${DARK_THEME.border}`,
            backgroundColor: DARK_THEME.cardBackground,
            color: DARK_THEME.text,
            fontSize: 14
          }}
        />
        <button
          onClick={handleScan}
          disabled={isLoading}
          style={{
            padding: '12px 24px',
            backgroundColor: isLoading ? DARK_THEME.border : DARK_THEME.primary,
            color: 'white',
            border: 'none',
            borderRadius: 6,
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: '600',
            transition: 'all 0.2s',
            ':hover': {
              backgroundColor: isLoading ? DARK_THEME.border : '#2980b9'
            }
          }}
        >
          {isLoading ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <FiClock /> 
              Scanning ({Math.round(progress * 100)}%)
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <FiLink />
              Launch Security Audit
            </div>
          )}
        </button>
      </div>

      {error && (
        <div style={{ 
          padding: 15,
          backgroundColor: '#e74c3c20',
          borderRadius: 6,
          marginBottom: 20,
          display: 'flex',
          alignItems: 'center',
          gap: 10
        }}>
          <FiAlertTriangle style={{ color: DARK_THEME.danger }} />
          <span style={{ color: DARK_THEME.danger }}>{error}</span>
        </div>
      )}

      {executiveSummary && (
        <div style={{ 
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: 20,
          marginBottom: 30
        }}>
          <div style={{ 
            backgroundColor: DARK_THEME.cardBackground,
            padding: 20,
            borderRadius: 10
          }}>
            <h3 style={{ marginTop: 0, marginBottom: 15 }}>
              <FiCheckCircle style={{ marginRight: 10 }} />
              Executive Summary
            </h3>
            <div style={{ display: 'grid', gap: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Scanned Hosts</span>
                <strong>{executiveSummary.totalHosts}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Critical Vulnerabilities</span>
                <strong style={{ color: DARK_THEME.danger }}>
                  {executiveSummary.criticalVulns}
                </strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Successful Exploits</span>
                <strong style={{ color: DARK_THEME.warning }}>
                  {executiveSummary.exploitSuccess}
                </strong>
              </div>
            </div>
          </div>

          {/* Compliance Dashboard */}
          <div style={{ 
            backgroundColor: DARK_THEME.cardBackground,
            padding: 20,
            borderRadius: 10
          }}>
            <h3 style={{ marginTop: 0, marginBottom: 15 }}>
              <FiShield style={{ marginRight: 10 }} />
              Compliance Status
            </h3>
            {Object.entries(compliance).map(([framework, data]) => (
              <div key={framework} style={{ marginBottom: 15 }}>
                <div style={{ 
                  display: 'flex', 
                  justifyContent: 'space-between',
                  marginBottom: 8
                }}>
                  <span>{framework.replace('_', ' ')}</span>
                  <span style={{ 
                    color: data.status === 'Pass' ? DARK_THEME.success : DARK_THEME.danger,
                    fontWeight: '600'
                  }}>
                    {data.passed}/{data.total}
                  </span>
                </div>
                <div style={{ 
                  height: 6,
                  backgroundColor: DARK_THEME.border,
                  borderRadius: 3
                }}>
                  <div style={{
                    width: `${(data.passed/data.total)*100}%`,
                    height: '100%',
                    backgroundColor: data.status === 'Pass' ? DARK_THEME.success : DARK_THEME.danger,
                    borderRadius: 3
                  }}></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {attackGraph && (
        <div style={{ 
          backgroundColor: DARK_THEME.cardBackground,
          padding: 20,
          borderRadius: 10,
          marginBottom: 30
        }}>
          <h3 style={{ marginTop: 0, marginBottom: 15 }}>
            🗺️ Attack Surface Visualization
          </h3>
          <div style={{ 
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
            gap: 15
          }}>
            {attackGraph.nodes.map(node => (
              <div key={node.id} style={{
                padding: 15,
                backgroundColor: 
                  node.group === 'host' ? '#2c3e50' :
                  node.group === 'vulnerability' ? '#e74c3c' :
                  '#f1c40f',
                color: 'white',
                borderRadius: 8,
                fontSize: 14,
                display: 'flex',
                flexDirection: 'column',
                gap: 8
              }}>
                <div style={{ 
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10
                }}>
                  {node.group === 'host' && <FiServer />}
                  {node.group === 'vulnerability' && <FiAlertTriangle />}
                  <strong>{node.label}</strong>
                </div>
                {node.severity && (
                  <div style={{ fontSize: 12 }}>
                    Severity: {node.severity}/10
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ... (Keep existing vulnerability display sections) ... */}

      <div style={{ 
        marginTop: 40, 
        padding: 20, 
        backgroundColor: DARK_THEME.cardBackground,
        borderRadius: 8,
        fontSize: '0.9em',
        textAlign: 'center',
        borderTop: `2px solid ${DARK_THEME.primary}`
      }}>
        © 2024 LogicBreach Technologies. All rights reserved. 
        Unauthorized security testing prohibited.
      </div>
    </div>
  );
}