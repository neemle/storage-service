import { Component, Input } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import type { ConsoleViewModel } from '../view-model';

@Component({
  selector: 'app-password-change-page',
  standalone: true,
  imports: [
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule
  ],
  templateUrl: './password-change-page.component.html'
})
export class PasswordChangePageComponent {
  @Input({ required: true }) app!: ConsoleViewModel;
}
