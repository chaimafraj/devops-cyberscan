import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ForcePassword } from './force-password';

describe('ForcePassword', () => {
  let component: ForcePassword;
  let fixture: ComponentFixture<ForcePassword>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ForcePassword],
    }).compileComponents();

    fixture = TestBed.createComponent(ForcePassword);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
