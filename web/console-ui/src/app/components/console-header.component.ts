import { Component, Input } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatToolbarModule } from '@angular/material/toolbar';
import type { ConsoleViewModel } from '../view-model';

@Component({
  selector: 'app-console-header',
  standalone: true,
  imports: [MatButtonModule, MatIconModule, MatToolbarModule],
  templateUrl: './console-header.component.html'
})
export class ConsoleHeaderComponent {
  @Input({ required: true }) app!: ConsoleViewModel;
}
