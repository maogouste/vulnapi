import axios from 'axios';
import type {
  Vulnerability,
  VulnerabilityDetail,
  ApiMode,
  ApiStats,
  Category,
  FlagResult,
  AuthResponse,
} from '../types';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests if available
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Documentation API
export const docsApi = {
  getMode: async (): Promise<ApiMode> => {
    const response = await api.get('/docs/mode');
    return response.data;
  },

  getStats: async (): Promise<ApiStats> => {
    const response = await api.get('/docs/stats');
    return response.data;
  },

  getCategories: async (): Promise<Category[]> => {
    const response = await api.get('/docs/categories');
    return response.data;
  },

  getVulnerabilities: async (category?: string): Promise<Vulnerability[]> => {
    const params = category ? { category } : {};
    const response = await api.get('/docs/vulnerabilities', { params });
    return response.data;
  },

  getVulnerability: async (id: string): Promise<VulnerabilityDetail> => {
    const response = await api.get(`/docs/vulnerabilities/${id}`);
    return response.data;
  },
};

// Auth API
export const authApi = {
  login: async (username: string, password: string): Promise<AuthResponse> => {
    const response = await api.post('/login', { username, password });
    return response.data;
  },

  register: async (username: string, email: string, password: string): Promise<AuthResponse> => {
    const response = await api.post('/register', { username, email, password });
    return response.data;
  },

  getCurrentUser: async () => {
    const response = await api.get('/users/me');
    return response.data;
  },
};

// Flags API
export const flagsApi = {
  submit: async (challengeId: string, flag: string): Promise<FlagResult> => {
    const response = await api.post('/flags/submit', {
      challenge_id: challengeId,
      flag,
    });
    return response.data;
  },

  getProgress: async () => {
    const response = await api.get('/flags/progress');
    return response.data;
  },
};

export interface RequestResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  data: unknown;
}

// Generic API call for the console
export const executeRequest = async (
  method: string,
  endpoint: string,
  body?: unknown,
  headers?: Record<string, string>
): Promise<RequestResult> => {
  try {
    const config = {
      method: method.toLowerCase(),
      url: endpoint.startsWith('/') ? endpoint : `/${endpoint}`,
      data: body,
      headers: headers || {},
    };

    const response = await axios({
      ...config,
      baseURL: '',
      validateStatus: () => true, // Don't throw on error status
    });

    // Convert headers to simple Record<string, string>
    const responseHeaders: Record<string, string> = {};
    Object.entries(response.headers).forEach(([key, value]) => {
      if (typeof value === 'string') {
        responseHeaders[key] = value;
      }
    });

    return {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      data: response.data,
    };
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return {
        status: error.response?.status || 0,
        statusText: error.message,
        headers: {},
        data: error.response?.data || { error: error.message },
      };
    }
    throw error;
  }
};

export default api;
