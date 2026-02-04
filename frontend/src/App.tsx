import { useState, useEffect, useCallback } from 'react';
import { Shield, Activity, Bell, Settings, AlertTriangle, Info, XCircle, Check, Trash2, Plus, Power, PowerOff } from 'lucide-react';
import { api, getToken, clearToken } from './api';
import { useWebSocket } from './useWebSocket';
import { Alert, Rule, SourceStatus, SystemStats } from './types';

function App() {
  const [authenticated, setAuthenticated] = useState(!!getToken());
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loginError, setLoginError] = useState('');

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [sources, setSources] = useState<SourceStatus[]>([]);
  const [stats, setStats] = useState<SystemStats | null>(null);
  
  const [activeTab, setActiveTab] = useState<'alerts' | 'rules' | 'sources'>('alerts');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [showRuleModal, setShowRuleModal] = useState(false);

  // WebSocket connection
  const handleNewAlert = useCallback((alert: Alert) => {
    setAlerts((prev) => [alert, ...prev].slice(0, 100));
    
    // Play alert sound for critical alerts
    if (alert.severity === 'critical') {
      playAlertSound();
    }
  }, []);

  const { connected } = useWebSocket(handleNewAlert);

  // Fetch data on mount
  useEffect(() => {
    if (authenticated) {
      loadData();
      const interval = setInterval(loadData, 10000); // Refresh every 10s
      return () => clearInterval(interval);
    }
  }, [authenticated]);

  const loadData = async () => {
    try {
      const [alertsData, rulesData, sourcesData, statsData] = await Promise.all([
        api.getAlerts(100),
        api.getRules(),
        api.getSources(),
        api.getStats(),
      ]);
      setAlerts(alertsData);
      setRules(rulesData);
      setSources(sourcesData);
      setStats(statsData);
    } catch (err) {
      console.error('Failed to load data:', err);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');
    try {
      await api.login(username, password);
      setAuthenticated(true);
    } catch (err) {
      setLoginError('Invalid credentials');
    }
  };

  const handleLogout = () => {
    clearToken();
    setAuthenticated(false);
  };

  const handleAcknowledge = async (alertId: string) => {
    try {
      await api.acknowledgeAlert(alertId);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, acknowledged: true } : a))
      );
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
    }
  };

  const handleToggleRule = async (ruleId: string) => {
    try {
      await api.toggleRule(ruleId);
      await loadData();
    } catch (err) {
      console.error('Failed to toggle rule:', err);
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    if (!confirm('Delete this rule?')) return;
    try {
      await api.deleteRule(ruleId);
      await loadData();
    } catch (err) {
      console.error('Failed to delete rule:', err);
    }
  };

  const playAlertSound = () => {
    const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIGGS56+mkTgwKUqzn77RfGAg9j9nwz3snBSp+zPDaj0ALElyx6OyrVxQKSKXh8bllHAU2jdXvzHgsBSh7yvDckD4IEliwg+i==');
    audio.play().catch(() => {});
  };

  if (!authenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950">
        <div className="bg-gray-900 p-8 rounded-lg shadow-xl w-96">
          <div className="flex items-center justify-center mb-6">
            <Shield className="w-12 h-12 text-cyan-500" />
            <h1 className="text-3xl font-bold ml-3">PHOSOR</h1>
          </div>
          <p className="text-gray-400 text-center mb-6">Real-time Log Correlation Engine</p>
          <form onSubmit={handleLogin}>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full p-3 mb-4 bg-gray-800 border border-gray-700 rounded focus:outline-none focus:border-cyan-500"
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full p-3 mb-4 bg-gray-800 border border-gray-700 rounded focus:outline-none focus:border-cyan-500"
            />
            {loginError && (
              <p className="text-red-500 text-sm mb-4">{loginError}</p>
            )}
            <button
              type="submit"
              className="w-full p-3 bg-cyan-600 hover:bg-cyan-700 rounded font-semibold transition"
            >
              Login
            </button>
          </form>
          <p className="text-gray-500 text-xs text-center mt-4">
            Default: admin / secret
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950">
      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-800 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="w-8 h-8 text-cyan-500" />
            <h1 className="text-2xl font-bold">PHOSOR</h1>
            <div className="flex items-center space-x-2 ml-6">
              <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm text-gray-400">
                {connected ? 'Live' : 'Disconnected'}
              </span>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded transition"
          >
            Logout
          </button>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className="w-64 bg-gray-900 border-r border-gray-800 min-h-[calc(100vh-73px)]">
          <nav className="p-4 space-y-2">
            <button
              onClick={() => setActiveTab('alerts')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded transition ${
                activeTab === 'alerts' ? 'bg-cyan-600' : 'hover:bg-gray-800'
              }`}
            >
              <Bell className="w-5 h-5" />
              <span>Alerts</span>
              {alerts.filter((a) => !a.acknowledged).length > 0 && (
                <span className="ml-auto bg-red-500 px-2 py-1 rounded-full text-xs">
                  {alerts.filter((a) => !a.acknowledged).length}
                </span>
              )}
            </button>
            <button
              onClick={() => setActiveTab('rules')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded transition ${
                activeTab === 'rules' ? 'bg-cyan-600' : 'hover:bg-gray-800'
              }`}
            >
              <Settings className="w-5 h-5" />
              <span>Rules</span>
            </button>
            <button
              onClick={() => setActiveTab('sources')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded transition ${
                activeTab === 'sources' ? 'bg-cyan-600' : 'hover:bg-gray-800'
              }`}
            >
              <Activity className="w-5 h-5" />
              <span>Sources</span>
            </button>
          </nav>

          {/* Stats */}
          {stats && (
            <div className="p-4 border-t border-gray-800">
              <h3 className="text-sm font-semibold text-gray-400 mb-3">System Stats</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Events:</span>
                  <span className="font-mono">{stats.total_events.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Alerts:</span>
                  <span className="font-mono">{stats.total_alerts.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Active Rules:</span>
                  <span className="font-mono">{stats.active_rules}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Uptime:</span>
                  <span className="font-mono">{formatUptime(stats.uptime_seconds)}</span>
                </div>
              </div>
            </div>
          )}
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6">
          {activeTab === 'alerts' && <AlertsView alerts={alerts} onAcknowledge={handleAcknowledge} onSelect={setSelectedAlert} />}
          {activeTab === 'rules' && <RulesView rules={rules} onToggle={handleToggleRule} onDelete={handleDeleteRule} />}
          {activeTab === 'sources' && <SourcesView sources={sources} />}
        </main>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <AlertDetailModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      )}
    </div>
  );
}

// Alert severity icon and color
function getSeverityConfig(severity: string) {
  switch (severity) {
    case 'critical':
      return { icon: XCircle, color: 'text-red-500', bg: 'bg-red-500/10' };
    case 'warning':
      return { icon: AlertTriangle, color: 'text-yellow-500', bg: 'bg-yellow-500/10' };
    default:
      return { icon: Info, color: 'text-blue-500', bg: 'bg-blue-500/10' };
  }
}

function AlertsView({ alerts, onAcknowledge, onSelect }: any) {
  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Real-time Alerts</h2>
      <div className="space-y-3">
        {alerts.map((alert: Alert) => {
          const config = getSeverityConfig(alert.severity);
          const Icon = config.icon;
          return (
            <div
              key={alert.id}
              className={`p-4 rounded-lg border ${
                alert.acknowledged ? 'bg-gray-900 border-gray-800' : `${config.bg} border-gray-700`
              } cursor-pointer hover:border-gray-600 transition`}
              onClick={() => onSelect(alert)}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3 flex-1">
                  <Icon className={`w-5 h-5 mt-1 ${config.color}`} />
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <h3 className="font-semibold">{alert.rule_name}</h3>
                      <span className={`px-2 py-0.5 rounded text-xs ${config.color} ${config.bg}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-gray-400 text-sm mt-1">{alert.message}</p>
                    <p className="text-gray-500 text-xs mt-2">
                      {new Date(alert.timestamp).toLocaleString()} • {alert.matched_events.length} events
                    </p>
                  </div>
                </div>
                {!alert.acknowledged && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onAcknowledge(alert.id);
                    }}
                    className="ml-4 px-3 py-1 bg-cyan-600 hover:bg-cyan-700 rounded text-sm transition"
                  >
                    <Check className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          );
        })}
        {alerts.length === 0 && (
          <p className="text-gray-500 text-center py-12">No alerts yet</p>
        )}
      </div>
    </div>
  );
}

function RulesView({ rules, onToggle, onDelete }: any) {
  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Correlation Rules</h2>
        <button className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 rounded transition flex items-center space-x-2">
          <Plus className="w-4 h-4" />
          <span>Add Rule</span>
        </button>
      </div>
      <div className="space-y-3">
        {rules.map((rule: Rule) => (
          <div key={rule.id} className="p-4 rounded-lg bg-gray-900 border border-gray-800">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center space-x-2">
                  <h3 className="font-semibold">{rule.name}</h3>
                  <span className={`px-2 py-0.5 rounded text-xs ${
                    rule.type === 'threshold' ? 'bg-purple-500/10 text-purple-500' :
                    rule.type === 'correlation' ? 'bg-orange-500/10 text-orange-500' :
                    'bg-blue-500/10 text-blue-500'
                  }`}>
                    {rule.type}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-xs ${getSeverityConfig(rule.severity).color} ${getSeverityConfig(rule.severity).bg}`}>
                    {rule.severity}
                  </span>
                </div>
                {rule.description && (
                  <p className="text-gray-400 text-sm mt-1">{rule.description}</p>
                )}
              </div>
              <div className="flex items-center space-x-2 ml-4">
                <button
                  onClick={() => onToggle(rule.id)}
                  className={`p-2 rounded transition ${
                    rule.enabled ? 'bg-green-600 hover:bg-green-700' : 'bg-gray-700 hover:bg-gray-600'
                  }`}
                  title={rule.enabled ? 'Enabled' : 'Disabled'}
                >
                  {rule.enabled ? <Power className="w-4 h-4" /> : <PowerOff className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => onDelete(rule.id)}
                  className="p-2 bg-red-600 hover:bg-red-700 rounded transition"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SourcesView({ sources }: any) {
  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Log Sources</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {sources.map((source: SourceStatus, idx: number) => (
          <div key={idx} className="p-4 rounded-lg bg-gray-900 border border-gray-800">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold">{source.name}</h3>
              <div className={`w-2 h-2 rounded-full ${source.active ? 'bg-green-500' : 'bg-gray-500'}`} />
            </div>
            <div className="space-y-1 text-sm text-gray-400">
              <div className="flex justify-between">
                <span>Type:</span>
                <span className="font-mono">{source.type}</span>
              </div>
              <div className="flex justify-between">
                <span>Events:</span>
                <span className="font-mono">{source.events_received.toLocaleString()}</span>
              </div>
              {source.last_event && (
                <div className="flex justify-between">
                  <span>Last Event:</span>
                  <span className="font-mono text-xs">{new Date(source.last_event).toLocaleTimeString()}</span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function AlertDetailModal({ alert, onClose }: any) {
  const config = getSeverityConfig(alert.severity);
  const Icon = config.icon;
  
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-gray-900 rounded-lg max-w-4xl w-full max-h-[90vh] overflow-auto" onClick={(e) => e.stopPropagation()}>
        <div className="p-6 border-b border-gray-800">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Icon className={`w-6 h-6 ${config.color}`} />
              <h2 className="text-xl font-bold">{alert.rule_name}</h2>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-300">
              <XCircle className="w-6 h-6" />
            </button>
          </div>
        </div>
        
        <div className="p-6 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-gray-400 mb-2">Message</h3>
            <p>{alert.message}</p>
          </div>
          
          <div>
            <h3 className="text-sm font-semibold text-gray-400 mb-2">Matched Events ({alert.matched_events.length})</h3>
            <div className="space-y-2">
              {alert.matched_events.map((event: any, idx: number) => (
                <div key={idx} className="p-3 bg-gray-800 rounded text-sm font-mono">
                  <div className="text-gray-400 text-xs mb-1">
                    {new Date(event.timestamp).toLocaleString()} • {event.source}
                  </div>
                  <div className="text-gray-200 whitespace-pre-wrap break-all">{event.raw}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function formatUptime(seconds: number) {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

export default App;
