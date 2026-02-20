import { provideZonelessChangeDetection } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideAnimations } from '@angular/platform-browser/animations';
import { AppComponent } from './app/app.component';
import { loadRuntimeSettings } from './settings';

async function bootstrap(): Promise<void> {
  await loadRuntimeSettings();
  await bootstrapApplication(AppComponent, {
    providers: [provideZonelessChangeDetection(), provideAnimations()]
  });
}

bootstrap().catch((err) => console.error(err));
