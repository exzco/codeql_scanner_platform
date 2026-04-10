import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:22211/api/v1',
});

export const getRepoList = (page = 1, perPage = 20) => 
    api.get(`/repos/list?page=${page}&per_page=${perPage}`);

export const addRepo = (data: any) => 
    api.post('/repos', data);

export const updateRepo = (id: number, data: any) => 
    api.post(`/repos/update/${id}`, data);

export const deleteRepo = (id: number) => 
    api.post(`/repos/delete/${id}`);

export const triggerScan = (repoId: number) =>
  api.post('/scan/tasks', { repo_id: repoId });

export const getScanTasks = (page = 1, perPage = 20, repoId?: number, status?: string) => {
    const params = new URLSearchParams({
        page: String(page),
        per_page: String(perPage),
    });

    if (repoId) params.append('repo_id', String(repoId));
    if (status) params.append('status', status);

    return api.get(`/scan/ListTasks?${params.toString()}`);
};

export const getScanVulnerabilities = (taskId: number, page = 1, perPage = 20) =>
    api.get(`/scan/vulnerabilities?task_id=${taskId}&page=${page}&per_page=${perPage}`);
