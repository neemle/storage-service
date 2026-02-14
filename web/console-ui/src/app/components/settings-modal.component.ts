import { Component, Input } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import type { ConsoleViewModel } from '../view-model';

@Component({
  selector: 'app-settings-modal',
  standalone: true,
  imports: [MatButtonModule, MatFormFieldModule, MatInputModule],
  templateUrl: './settings-modal.component.html'
})
export class SettingsModalComponent {
  @Input({ required: true }) app!: ConsoleViewModel;
}
