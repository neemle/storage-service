import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatListModule } from '@angular/material/list';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import type { ReplicaSubMode } from '../../types';
import type { ConsoleViewModel } from '../view-model';

@Component({
  selector: 'app-storage-admin',
  standalone: true,
  imports: [
    CommonModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatListModule,
    MatSelectModule,
    MatSlideToggleModule
  ],
  templateUrl: './storage-admin.component.html'
})
export class StorageAdminComponent {
  @Input({ required: true }) app!: ConsoleViewModel;

  readonly replicaSubModes: ReplicaSubMode[] = ['delivery', 'backup'];
}
