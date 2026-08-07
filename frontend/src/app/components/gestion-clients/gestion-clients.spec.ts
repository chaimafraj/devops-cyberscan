import { of, throwError } from 'rxjs';

import { GestionClients } from './gestion-clients';

describe('GestionClients', () => {
  let component: GestionClients;
  let clientService: any;

  beforeEach(() => {
    clientService = {
      getClients: vi.fn(() => of({
        results: [], count: 0, total_pages: 1, current_page: 1,
      })),
      createClient: vi.fn(),
      deleteClient: vi.fn(),
    };
    component = new GestionClients(
      clientService,
      { detectChanges: vi.fn() } as any,
    );
    component.showAddForm = true;
    component.newNom = 'Client test';
    component.newUsername = 'client-test';
    component.newEmail = 'client@example.com';
  });

  it('shows success only when the backend confirms email delivery', () => {
    clientService.createClient.mockReturnValue(of({ email_status: 'envoyé' }));

    component.createClient();

    expect(component.successMessage).toContain('email envoyé');
    expect(component.error).toBe('');
  });

  it('does not show success for a legacy email failure response', () => {
    clientService.createClient.mockReturnValue(of({ email_status: 'échec: SMTP unavailable' }));

    component.createClient();

    expect(component.successMessage).toBe('');
    expect(component.error).toContain('SMTP unavailable');
    expect(component.showAddForm).toBe(false);
  });

  it('keeps the form available when the backend rejects creation', () => {
    clientService.createClient.mockReturnValue(throwError(() => ({
      error: { error: 'SMTP indisponible' },
    })));

    component.createClient();

    expect(component.addError).toBe('SMTP indisponible');
    expect(component.showAddForm).toBe(true);
    expect(component.newEmail).toBe('client@example.com');
  });
});
