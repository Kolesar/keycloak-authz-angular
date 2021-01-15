import {Injectable} from '@angular/core';
import {throwError} from 'rxjs';
import {catchError, map as __map} from 'rxjs/operators';
import {HttpClient, HttpErrorResponse, HttpHeaders, HttpParameterCodec, HttpParams} from '@angular/common/http';
import t from 'typy';
import {KeycloakAuthzOptions} from '../interfaces/keycloak-authz-options';
import {KeycloakAuthzInitOptions} from '../interfaces/keycloak-authz-init-options';
import {
    KeycloakAuthorizationRequest,
    KeycloakAuthorizationRequestMetaData,
    ResourcePermission
} from '../interfaces/keycloak-authorization-request';
import {KeycloakResourcePermission, KeycloakResourcePermissionsCheck} from '../interfaces/keycloak-permissions';
import {KeycloakConfig} from 'keycloak-js';

/**
 * Custom parameter codec to correctly handle the plus sign in parameter
 * values. See https://github.com/angular/angular/issues/18261
 */
class ParameterCodec implements HttpParameterCodec {
  encodeKey(key: string): string {
    return encodeURIComponent(key);
  }

  encodeValue(value: string): string {
    return encodeURIComponent(value);
  }

  decodeKey(key: string): string {
    return decodeURIComponent(key);
  }

  decodeValue(value: string): string {
    return decodeURIComponent(value);
  }
}
const PARAMETER_CODEC = new ParameterCodec();

@Injectable({
  providedIn: 'root'
})
export class KeycloakAuthorizationService {

    private authConfig = null;
    private keycloakConfig: KeycloakConfig = null;

    /**
     * Indicates that the permission for the default resource server be loaded at the adapter initialization
     */
    private _loadPermissionsInStartup: boolean;

    /**
     * Defines the resource-server of which the permissions are loaded at adapter initialization
     */
    private _defaultResourceServerId: string;

    /**
     * Contains the RPT-Token after successful Get-Entitlement-Call
     */
    private _rpt: string = null;

    /**
     * Contains all permissions decoded from the RPT-Token after successful Get-Entitlement-Call
     */
    private _permissions:any[] = [];

  constructor(private http:HttpClient) {
  }

  private newParams(): HttpParams {
    return new HttpParams({
      encoder: PARAMETER_CODEC
    });
  }

  /**
   * Handles the class values initialization.
   */
  private initServiceValues({
    loadPermissionsInStartup = true,
    defaultResourceServerId = null

  }: KeycloakAuthzInitOptions): void {
    this._loadPermissionsInStartup = loadPermissionsInStartup;
    this._defaultResourceServerId = defaultResourceServerId;
  }


  /**
   * KeycloakAuthorization initialization. It should be called to initialize the adapter.
   * Options is a object with 2 main parameters: config and initOptions. The first one
   * will be used to connect to Keycloak. The second one are options to initialize the
   * keycloak authorization instance.
   *
   * @param options
   * config: an object with the following content:
   * - url: Keycloak json URL
   * - realm: realm name
   * - clientId: client id
   *
   * initOptions:
   * - defaultResourceServerId: specifies the default resource-server
   * - loadPermissionsInStartup: if set to true, load all permissions for default resource-server at initialization of adapter
   *
   *
   */
  init(options: KeycloakAuthzOptions){

      const { config, initOptions } = options;
      this.initServiceValues(initOptions);

      this.keycloakConfig = config;
      // console.log(this._defaultResourceServerId)

      return new Promise((resolve, reject) => {
        this.http.get(
            this.keycloakConfig.url + '/realms/' + this.keycloakConfig.realm + '/.well-known/uma2-configuration'
        ).subscribe(async res => {
          this.authConfig=res;
          if ((this._defaultResourceServerId) && (this._loadPermissionsInStartup)){
            try{
                await this.getAuthorizations(this._defaultResourceServerId,{});
            } catch (err){
                reject ('Error getting authorizations for resource-server-id ' + this._defaultResourceServerId)

            }
          }
          resolve(res);
        }, err => {
            const msg='Fehler bei der Initialisierung des Keycloak-Authorization-Services';
            reject(msg);
        });
      });
  }

  /**
   * Checks if user has the required access to a resource and/or scope.
   *
   * @param authorization-check object
   * - rsname : Name of the resource
   * - scope : name of the scope
   *
   *
   * @returns boolean true if user has access, false if not
   */
  public checkAuthorization(authorization:KeycloakResourcePermissionsCheck) {
      return this.hasAuthorization(authorization);
  }

  /**
   * Internal method to check if user has the required access to a resource and/or scope
   *
   * @returns boolean true if user has access, false if not
   */
  private hasAuthorization(authorization:KeycloakResourcePermissionsCheck):boolean{

      const checkForResource = t(authorization,'rsname').safeObject;
      const checkForScope = t(authorization,'scope').safeObject;

      if (!t(this._permissions).isEmptyArray){
          const filteredResource = this._permissions.find(t => {if (t.rsname === checkForResource) return t;});
          // No access to resource
          if (!t(filteredResource).isObject){
              // console.log("no access to resource granted");
              return false;
          }
          // access to resource granted and no scope checking required
          if (checkForScope === undefined){
              // console.log("no scope checking required.required auth is present - hooray");
              return true;
          }
          // scope checking required, but resource has no scope defined
          if (t(filteredResource.scopes).isEmptyArray){
              // console.log("scope checking required, but no scopes defined for resource");
              return false;
          }
          const filteredScope = filteredResource.scopes.find(t => { if (t === checkForScope) return t;});
          // no access to scope
          if (t(filteredScope).isUndefined ){
              // console.log("required scope not found");
              return false;
          }
          // console.log("required auth is present - hooray");
          return true;
      }
      // console.log("no permissions loaded (yet)");
      return false;

  }

  /**
   * Return an array of all permissions present for the logged-in user
   *
   * @returns Array of permissions
   */
  public getPermissions():KeycloakResourcePermission[]{
      return this._permissions;

  }

  /**
   * Gets authorizations for resource-server from keycloak. Also stores the permissions for future use
   *
   * @param resourceServerId
   * The resource server for which the entitlements of the current user are checked
   *
   * @param authorizationRequest
   * description missing
   *
   * @returns Authorizations-Object
   */
  public getAuthorizations(resourceServerId, authorizationRequest:KeycloakAuthorizationRequest) {
    return new Promise((resolve, reject) => {
        this.getEntitlement(resourceServerId, authorizationRequest)
            .subscribe(res => {
                try {

                    let permissions = [];
                    if (res.access_token) {
                        this._rpt = res.access_token;
                        const decoded = this.decodeToken(res.access_token);
                        if (decoded.authorization) {
                            if (decoded.authorization.permissions) {
                                permissions = decoded.authorization.permissions;
                            }
                        }
                    }
                    this._permissions = permissions;

                    resolve(permissions);
                } catch (error) {
                    reject(error);
                }
            }, error => {
                const msg = 'Unable to get entitlements';
                reject(msg);
            });
    });
  }

  /**
   * Gets entitlement front resource-server from keycloak
   *
   * @param resourceServerId
   * The resource server for which the entitlements of the current user are checked
   *
   * @param authorizationRequest
   * description missing
   *
   * @returns Object with RPT-Token containing the authorizations/entitlement
   */
  private getEntitlement(resourceServerId, authorizationRequest:KeycloakAuthorizationRequest) {
    let newParams = this.newParams();
    let httpHeaders = new HttpHeaders();

    httpHeaders = httpHeaders.set('Content-type', 'application/x-www-form-urlencoded');

    if (!authorizationRequest) {
       authorizationRequest = {};
    }

    newParams = newParams.set('grant_type', 'urn:ietf:params:oauth:grant-type:uma-ticket');
    newParams = newParams.set('client_id', this.keycloakConfig.clientId);
    newParams = newParams.set('audience', resourceServerId);

    if (authorizationRequest.claimToken) {
        newParams = newParams.set('claim_token',authorizationRequest.claimToken);
        if (authorizationRequest.claimTokenFormat) {
            newParams = newParams.set('claim_token_format',authorizationRequest.claimTokenFormat);
        }
    }

    let permissions:ResourcePermission[] = authorizationRequest.permissions;

    if (!permissions) {
        permissions = [];
    }

    for (const permission of permissions) {
        let resourceId = permission.id;

        if (permission.scopes && permission.scopes.length > 0) {
            resourceId += '#';
            for (const scope of permission.scopes) {
                if (resourceId.indexOf('#') !== resourceId.length - 1) {
                    resourceId += ',';
                }
                resourceId += scope;
            }
        }

        newParams = newParams.append('permission', resourceId);
    }

    const metadata:KeycloakAuthorizationRequestMetaData = authorizationRequest.metadata;

    if (metadata) {
        if (metadata.responseIncludeResourceName) {
            newParams = newParams.set('response_include_resource_name',metadata.responseIncludeResourceName);

        }
        if (metadata.responsePermissionsLimit) {
            newParams = newParams.set('response_permissions_limit',metadata.responsePermissionsLimit.toString());
        }
    }

    if (this._rpt) {
        newParams = newParams.set('rpt',this._rpt);
    }

    return this.http.post<any>(this.authConfig.token_endpoint, newParams.toString(), {
        headers: httpHeaders,
        responseType: 'json'
    })
    .pipe(
        catchError(this.handleError),
        __map((_r) => {
          // console.log(_r);
          return _r;
        })
    );
  }

  /**
   * Decodes RPT-Token
   *
   * @param str - encoded token string
   *
   * @returns Decoded jwt-token object
   *
   */
  private decodeToken(str) {
            str = str.split('.')[1];

            str = str.replace('/-/g', '+');
            str = str.replace('/_/g', '/');
            switch (str.length % 4)
            {
                case 0:
                    break;
                case 2:
                    str += '==';
                    break;
                case 3:
                    str += '=';
                    break;
                default:
                    throw new Error('Invalid token');
            }

            str = (str + '===').slice(0, str.length + (str.length % 4));
            str = str.replace(/-/g, '+').replace(/_/g, '/');

            str = decodeURIComponent(escape(atob(str)));

            str = JSON.parse(str);
            return str;
    }

    private handleError(error: HttpErrorResponse) {
      if (error.error instanceof ErrorEvent) {
        // A client-side or network error occurred. Handle it accordingly.
        console.error('An error occurred:', error.error.message);
      } else {
        // The backend returned an unsuccessful response code.
        // The response body may contain clues as to what went wrong,
        console.error(
          `Backend returned code ${error.status}, ` +
          `body was: ${error.error}`);
      }
      // return an observable with a user-facing error message
      return throwError(
        'Something bad happened; please try again later.');
    };
}
