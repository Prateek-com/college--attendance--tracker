/**
 * API Service - Connects React frontend to FastAPI backend
 * All data is stored in MongoDB for permanent persistence
 */

// Dynamic API URL - uses same host as frontend but port 8000
const getApiBaseUrl = () => {
  // Check for explicit env variable first
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL;
  }
  
  // Auto-detect: use same hostname as current page, but port 8000
  const hostname = window.location.hostname;
  return `http://${hostname}:8000`;
};

const API_BASE_URL = getApiBaseUrl();

interface ApiResponse<T> {
  data?: T;
  error?: string;
}

// Store token in memory (will also persist to localStorage for page refresh)
let authToken: string | null = null;

export function setAuthToken(token: string | null) {
  authToken = token;
  if (token) {
    localStorage.setItem('auth_token', token);
  } else {
    localStorage.removeItem('auth_token');
  }
}

export function getAuthToken(): string | null {
  if (!authToken) {
    authToken = localStorage.getItem('auth_token');
  }
  return authToken;
}

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> {
  const token = getAuthToken();
  
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  if (token) {
    (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
  }

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    const data = await response.json();

    if (!response.ok) {
      return { error: data.detail || 'An error occurred' };
    }

    return { data };
  } catch (error) {
    console.error('API Error:', error);
    return { error: 'Failed to connect to server. Make sure backend is running on port 8000.' };
  }
}

// Auth API
export const authApi = {
  async register(name: string, email: string, password: string) {
    return apiRequest<{
      access_token: string;
      user: { id: string; name: string; email: string; created_at: string };
    }>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password }),
    });
  },

  async login(email: string, password: string) {
    return apiRequest<{
      access_token: string;
      user: { id: string; name: string; email: string; created_at: string };
    }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  async getMe() {
    return apiRequest<{ id: string; name: string; email: string; created_at: string }>(
      '/api/auth/me'
    );
  },
};

// Subjects API
export const subjectsApi = {
  async getAll() {
    return apiRequest<Array<{
      id: string;
      user_id: string;
      name: string;
      color: string;
      created_at: string;
    }>>('/api/subjects');
  },

  async create(name: string) {
    return apiRequest<{
      id: string;
      user_id: string;
      name: string;
      color: string;
      created_at: string;
    }>('/api/subjects', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  },

  async delete(id: string) {
    return apiRequest<{ message: string }>(`/api/subjects/${id}`, {
      method: 'DELETE',
    });
  },
};

// Attendance API
export const attendanceApi = {
  async getBySubject(subjectId: string) {
    return apiRequest<Array<{
      id: string;
      subject_id: string;
      date: string;
      status: string;
    }>>(`/api/attendance/${subjectId}`);
  },

  async mark(subjectId: string, date: string, status: 'present' | 'absent') {
    return apiRequest<{
      id: string;
      subject_id: string;
      date: string;
      status: string;
    }>('/api/attendance', {
      method: 'POST',
      body: JSON.stringify({ subject_id: subjectId, date, status }),
    });
  },

  async getStats(subjectId: string) {
    return apiRequest<{
      total: number;
      present: number;
      absent: number;
      percentage: number;
    }>(`/api/attendance/${subjectId}/stats`);
  },
};
