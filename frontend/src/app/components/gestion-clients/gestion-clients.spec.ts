import { ComponentFixture, TestBed } from '@angular/core/testing';

import { GestionClients } from './gestion-clients';

describe('GestionClients', () => {
  let component: GestionClients;
  let fixture: ComponentFixture<GestionClients>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [GestionClients],
    }).compileComponents();

    fixture = TestBed.createComponent(GestionClients);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
