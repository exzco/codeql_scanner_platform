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
