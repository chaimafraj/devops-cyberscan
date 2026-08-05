import { Component, OnInit } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { Navbar } from './components/navbar/navbar';
import { ToastComponent } from './components/toast/toast';
import { ChatbotWidget } from './components/chatbot-widget/chatbot-widget';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, Navbar, ToastComponent, ChatbotWidget],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App implements OnInit {
  title = 'frontend';

  ngOnInit() {
    const savedTheme = sessionStorage.getItem('theme') || 'dark';
    document.body.setAttribute('data-theme', savedTheme);
  }
}
