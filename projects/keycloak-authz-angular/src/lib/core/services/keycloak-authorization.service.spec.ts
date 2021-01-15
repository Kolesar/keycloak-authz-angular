import { TestBed } from '@angular/core/testing';

import { KeycloakAuthorizationService } from './keycloak-authorization.service';

describe('KeycloakAuthorizationService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: KeycloakAuthorizationService = TestBed.inject(KeycloakAuthorizationService);
    expect(service).toBeTruthy();
  });
});
