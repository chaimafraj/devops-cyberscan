import { TestBed } from '@angular/core/testing';
import { AuthService } from './auth.service'; // 🆕 Baddalna 'Auth' b 'AuthService'

describe('AuthService', () => {
  let service: AuthService; // 🆕 Class type s7i7a

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(AuthService); // 🆕 Injecter el class el s7i7a
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
