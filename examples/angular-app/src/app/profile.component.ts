import { Component } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({ selector: 'app-profile', template: '<div [innerHTML]="html"></div>' })
export class ProfileComponent {
  html: any;

  constructor(private sanitizer: DomSanitizer) {}

  load(): void {
    // The fragment is attacker-controlled; bypassing the sanitizer makes it XSS.
    const raw = location.hash;
    this.html = this.sanitizer.bypassSecurityTrustHtml(raw);
  }
}
