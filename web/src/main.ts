import { Component } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';

@Component({
  selector: 'bwu-root',
  standalone: true,
  template: `<main><p class="eyebrow">SERVER · FOUNDATION</p><h1>BaradWatchU</h1><p>Server dashboard bootstrap</p><section><h2>Not connected</h2><p>Device enrollment, policies, audit history and reporting are planned. No fleet data is available in this bootstrap.</p></section></main>`,
  styleUrl: './styles.css'
})
class AppComponent {}

bootstrapApplication(AppComponent).catch((error: unknown) => console.error(error));
