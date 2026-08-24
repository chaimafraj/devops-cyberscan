import { Component, OnInit } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { Navbar } from './components/navbar/navbar';
import { ToastComponent } from './components/toast/toast';
import { ChatbotWidget } from './components/chatbot-widget/chatbot-widget';
import { ThemeService } from './services/theme.service';
import { MatrixBackground } from './components/matrix-background/matrix-background';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, Navbar, ToastComponent, ChatbotWidget, MatrixBackground],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App implements OnInit {
  title = 'frontend';

  constructor(private readonly themeService: ThemeService) {}

  ngOnInit(): void {
    this.themeService.initialize();
  }
}
