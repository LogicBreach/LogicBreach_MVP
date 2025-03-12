import React, { useState } from 'react';
import axios from 'axios';
import { PieChart, Pie, Cell, Tooltip } from 'recharts';
import { FiAlertTriangle, FiClock, FiServer } from 'react-icons/fi';
import ReactFlow, { Controls } from 'reactflow';
import 'reactflow/dist/style.css';

const DARK_THEME = {
  background: '#0a0a0a',
  text: '#ffffff',
  cardBackground: '#1a1a1a',
  primary: '#3498db',
  danger: '#e74c3c',
  success: '#2ecc71'
};

const COLORS = ['#e74c3c', '#f39c12', '#2ecc71', '#3498db'];

const AttackNode = ({ data }) => (
  <div style={{
    padding: '15px',
    background: DARK_THEME.cardBackground,
    borderRadius: '8px',
    border: `2px solid ${data?.severity > 8 ? DARK_THEME.danger : DARK_THEME.primary}`
  }}>
    <h4 style={{ margin: 0 }}>{(data?.stage || 'vulnerability').replace('_', ' ')}</h4>
    <p style={{ color: '#7f8c8d' }}>{data?.vulnName || 'Security issue detected'}</p>
  </div>
);

export default function App() {
  const [target, setTarget] = useState('');
  const [results, setResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [attackGraph, setAttackGraph] = useState([]);

  const handleScan = async () => {
    setError('');
    setIsLoading(true);
    try {
      const response = await axios.post('http://localhost:3001/scan', { target });
      
      if (response.data?.error) throw new Error(response.data.error);
      if (!response.data?.results) throw new Error('No scan results received');

      // Build attack graph safely
      const criticalVulns = response.data.results
        ?.flatMap(h => h.vulnerabilities ?? [])
        ?.filter(v => v?.severity >= 9) ?? [];

      const graphNodes = criticalVulns.map((vuln, idx) => ({
        id: `node-${idx}`,
        position: { x: idx * 300, y: 0 },
        data: {
          stage: vuln?.category === 'Windows' ? 'initial_access' : 'exploitation',
          vulnName: vuln?.name,
          severity: vuln?.severity
        }
      }));

      setAttackGraph(graphNodes);
      setResults(response.data);
      setIsLoading(false);

    } catch (err) {
      setError(err.message);
      setIsLoading(false);
    }
  };

  const severityData = results?.results?.reduce((acc, host) => {
    host?.vulnerabilities?.forEach(v => {
      if (v?.severity) acc[v.severity] = (acc[v.severity] || 0) + 1;
    });
    return acc;
  }, {});

  return (
    <div style={{ 
      maxWidth: 1400,
      margin: '0 auto',
      padding: 20,
      backgroundColor: DARK_THEME.background,
      minHeight: '100vh',
      color: DARK_THEME.text
    }}>
      {/* Scan Controls */}
      <div style={{ 
        backgroundColor: DARK_THEME.cardBackground,
        padding: 20,
        borderRadius: 10,
        marginBottom: 20,
        display: 'grid',
        gridTemplateColumns: '1fr auto',
        gap: 15
      }}>
        <input
          type="text"
          placeholder="Enter target (e.g., 192.168.1.1-10)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          style={{ 
            padding: 12,
            borderRadius: 6,
            border: `1px solid ${DARK_THEME.border}`,
            backgroundColor: DARK_THEME.cardBackground,
            color: DARK_THEME.text
          }}
        />
        <button
          onClick={handleScan}
          disabled={isLoading || !target}
          style={{
            padding: '12px 24px',
            backgroundColor: isLoading ? DARK_THEME.border : DARK_THEME.primary,
            color: 'white',
            border: 'none',
            borderRadius: 6,
            cursor: 'pointer',
            minWidth: '150px'
          }}
        >
          {isLoading ? <><FiClock /> Scanning...</> : 'Start Scan'}
        </button>
      </div>

      {/* Error Display */}
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

      {/* Attack Graph */}
      {attackGraph?.length > 0 && (
        <div style={{ height: 400, marginBottom: 30 }}>
          <ReactFlow 
            nodes={attackGraph}
            nodeTypes={{ custom: AttackNode }}
            fitView
          >
            <Controls />
          </ReactFlow>
        </div>
      )}

      {/* Scan Results */}
      {results?.results?.length > 0 && (
        <div style={{ 
          backgroundColor: DARK_THEME.cardBackground,
          padding: 20,
          borderRadius: 10
        }}>
          <h2 style={{ 
            color: DARK_THEME.text,
            borderBottom: `2px solid ${DARK_THEME.primary}`,
            paddingBottom: 10
          }}>
            <FiServer style={{ marginRight: 10 }} />
            Scan Results for: {results.target}
          </h2>

          {/* Severity Chart */}
          {Object.keys(severityData || {}).length > 0 && (
            <div style={{ margin: '20px 0' }}>
              <h3><FiAlertTriangle /> Vulnerability Severity Distribution</h3>
              <PieChart width={500} height={300}>
                <Pie
                  data={Object.entries(severityData).map(([severity, count]) => ({
                    name: `Severity ${severity}`,
                    value: count
                  }))}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  label
                >
                  {Object.keys(severityData).map((_, index) => (
                    <Cell key={index} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: DARK_THEME.cardBackground,
                    border: 'none'
                  }}
                  itemStyle={{ color: DARK_THEME.text }}
                />
              </PieChart>
            </div>
          )}

          {/* Host Results */}
          {results.results.map((host, idx) => (
            <div key={idx} style={{
              marginBottom: 15,
              padding: 15,
              borderLeft: `4px solid ${host.vulnerabilities?.length ? DARK_THEME.danger : DARK_THEME.success}`,
              backgroundColor: DARK_THEME.background,
              borderRadius: 5
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <div>
                  <h4 style={{ margin: 0 }}>{host.ip}</h4>
                  <p style={{ color: '#7f8c8d', margin: '5px 0' }}>
                    Open Ports: {host.open_ports?.join(', ') || 'None found'}
                  </p>
                </div>
                <div style={{
                  backgroundColor: host.vulnerabilities?.length ? DARK_THEME.danger : DARK_THEME.success,
                  color: 'white',
                  padding: '5px 15px',
                  borderRadius: 3
                }}>
                  {host.vulnerabilities?.length || 0} Issues
                </div>
              </div>

              {host.vulnerabilities?.map((vuln, vIdx) => (
                vuln && (
                  <div key={vIdx} style={{
                    marginTop: 10,
                    padding: 10,
                    backgroundColor: DARK_THEME.cardBackground,
                    borderRadius: 5
                  }}>
                    <p style={{ margin: 0, fontWeight: 'bold' }}>{vuln.name}</p>
                    <p style={{ margin: '5px 0', color: '#7f8c8d' }}>
                      {vuln.remediation}
                    </p>
                  </div>
                )
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}