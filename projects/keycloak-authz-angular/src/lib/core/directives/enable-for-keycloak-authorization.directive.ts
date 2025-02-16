import {Directive, ElementRef, Input, OnInit} from '@angular/core';
import {KeycloakService} from 'keycloak-angular';
import {KeycloakAuthorizationService} from '../services/keycloak-authorization.service';
import {KeycloakResourcePermissionsCheck} from '../interfaces/keycloak-permissions';


@Directive({
  selector: '[libEnableForKeycloakAuthorization]'
})
export class EnableForKeycloakAuthorizationDirective implements OnInit {

    @Input('libEnableForKeycloakAuthorization') requiredAuthorization: string;

    constructor(
        private element: ElementRef,
        private keycloakAngular: KeycloakService,
        private authService:KeycloakAuthorizationService
    ) { }

    ngOnInit() {
        this.noAuthPresentAction();

        let authCheck = {} as KeycloakResourcePermissionsCheck;
        if (this.requiredAuthorization.includes('#')){
            const authArr = this.requiredAuthorization.split('#');
            authCheck = {
                 rsname:authArr[0],
                 scope:authArr[1]
            };
        } else {
            authCheck = {
                 rsname:this.requiredAuthorization
             };
        }

        this.keycloakAngular.isLoggedIn().then(res => {
            if(this.authService.checkAuthorization(authCheck)){
                this.authPresentAction();

            }
        });
     }

     private authPresentAction(){
         this.element.nativeElement.disabled = false;
     }

     private noAuthPresentAction(){
         this.element.nativeElement.disabled = true;
     }
}
