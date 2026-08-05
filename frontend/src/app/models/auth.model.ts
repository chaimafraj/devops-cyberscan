export type UserRole = 'admin' | 'analyst' | 'viewer' | 'client';

export interface User {
  id?: number;
  username: string;
  email?: string;
  nom?: string;
  role: UserRole;
  must_change_password?: boolean;
}

export interface AuthResponse {
  access: string;
  refresh: string;
  user: User;
  message?: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  role: UserRole;
}

export interface ChangePasswordRequest {
  old_password: string;
  new_password: string;
}
