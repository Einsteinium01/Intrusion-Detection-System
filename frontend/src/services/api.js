import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 5000,
});

export const apiService = {
  // Fetch available network interfaces
  async getInterfaces() {
    const response = await apiClient.get('/interfaces');
    return response.data;
  },

  // Start packet capture & detection engine
  async startMonitoring(mode = 'LIVE', interfaceName = null) {
    const response = await apiClient.post('/start', { mode, interface: interfaceName });
    return response.data;
  },

  // Stop capture engine
  async stopMonitoring() {
    const response = await apiClient.post('/stop');
    return response.data;
  },

  // Get live engine status and metrics DTO
  async getStatus() {
    const response = await apiClient.get('/status');
    return response.data;
  },

  // Get recent threat alerts
  async getAlerts(limit = 50) {
    const response = await apiClient.get('/alerts', { params: { limit } });
    return response.data;
  },

  // Get recent packet logs
  async getLogs(limit = 50) {
    const response = await apiClient.get('/logs', { params: { limit } });
    return response.data;
  },

  // Get active network flows
  async getFlows(limit = 100) {
    const response = await apiClient.get('/flows', { params: { limit } });
    return response.data;
  },

  // Get model metadata & specifications
  async getModelInfo() {
    const response = await apiClient.get('/model-info');
    return response.data;
  },

  // Export CSV URL generator
  getExportCsvUrl(type = 'alerts', limit = 500) {
    return `${API_BASE_URL}/export/csv?type=${encodeURIComponent(type)}&limit=${limit}`;
  },

  // Trigger on-demand AI analysis for a specific threat
  async triggerAiAnalysis(alert) {
    const response = await axios.post('http://localhost:5000/api/ai/analyze-threat', { alert });
    return response.data;
  },

  // Ask AI / LLM about threats or investigation
  async investigateThreat(alertId, question) {
    const response = await axios.post('http://localhost:5000/api/ai/investigate', {
      alert_id: alertId || '',
      question,
    });
    return response.data;
  },

  // Get AI status and model health
  async getAiStatus() {
    const response = await axios.get('http://localhost:5000/api/ai/status');
    return response.data;
  },
};

export default apiService;

