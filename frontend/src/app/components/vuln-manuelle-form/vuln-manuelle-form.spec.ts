import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';

import { VulnManuelleForm } from './vuln-manuelle-form';

describe('VulnManuelleForm', () => {
  let component: VulnManuelleForm;
  let fixture: ComponentFixture<VulnManuelleForm>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [VulnManuelleForm],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    fixture = TestBed.createComponent(VulnManuelleForm);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    await fixture.whenStable();

    const initReq = httpMock.expectOne('http://127.0.0.1:8000/api/vuln-templates/');
    initReq.flush({});
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
