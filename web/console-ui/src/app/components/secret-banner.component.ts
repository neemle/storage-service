import { Component, Input } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import type { ConsoleViewModel } from '../view-model';

@Component({
  selector: 'app-secret-banner',
  standalone: true,
  imports: [MatButtonModule, MatCardModule, MatIconModule],
  templateUrl: './secret-banner.component.html'
})
export class SecretBannerComponent {
  @Input({ required: true }) app!: ConsoleViewModel;
}
