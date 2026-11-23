import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Pishing_domain from '../Frontend/src/pages/Pishing_domain.jsx';
import axios from 'axios';
import toast from 'react-hot-toast';

jest.mock('axios');
jest.mock('react-hot-toast', () => ({
  error: jest.fn(),
  success: jest.fn()
}));

// Helper to render component with a fake token
const renderComponent = () => {
  localStorage.setItem('token', 'fake-token');
  return render(<Pishing_domain />);
};

describe('Pishing_domain component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.clear();
  });

  test('renders without crashing and shows loading spinner for live data', () => {
    axios.get.mockResolvedValueOnce({ data: { total_urls: 0, analysis: [] } });
    renderComponent();
    expect(screen.getByText(/Threat Scanner/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Scan URL/i })).toBeInTheDocument();
    expect(screen.getByTestId('loader')).toBeInTheDocument();
  });

  test('fetches live data on mount and displays list items', async () => {
    const liveResponse = {
      data: {
        total_urls: 2,
        analysis: [
          { url: 'https://bad.com', reason: 'phishing' },
          { url: 'https://evil.com', reason: 'malware' }
        ]
      }
    };
    axios.get.mockResolvedValueOnce(liveResponse);
    renderComponent();

    await waitFor(() => expect(axios.get).toHaveBeenCalledWith('http://127.0.0.1:8000/domains/live'));

    // Verify total count
    expect(screen.getByText(/Total Monitored: 2/i)).toBeInTheDocument();

    // Verify each threat item
    expect(screen.getByText('https://bad.com')).toBeInTheDocument();
    expect(screen.getByText('https://evil.com')).toBeInTheDocument();

    // Verify analysis report text
    expect(screen.getByText('phishing')).toBeInTheDocument();
  });

  test('handles scanning success with safe domain', async () => {
    axios.get.mockResolvedValueOnce({ data: { total_urls: 0, analysis: [] } });
    axios.post.mockResolvedValueOnce({
      data: { is_phishing: false, url: 'https://safe.com', reason: 'No issues found' }
    });

    renderComponent();

    const input = screen.getByPlaceholderText(/https:\/\/example.com/i);
    fireEvent.change(input, { target: { value: 'https://safe.com' } });

    const button = screen.getByRole('button', { name: /Scan URL/i });
    fireEvent.click(button);

    expect(button).toBeDisabled();
    expect(screen.getByText(/Analyzing.../i)).toBeInTheDocument();

    await waitFor(() => expect(axios.post).toHaveBeenCalled());

    // Success toast called
    expect(toast.success).toHaveBeenCalledWith('Domain appears to be safe.');

    // Result card appears
    expect(screen.getByText(/Safe Domain/i)).toBeInTheDocument();
    expect(screen.getByText('https://safe.com')).toBeInTheDocument();
    expect(screen.getByText('No issues found')).toBeInTheDocument();

    // Button re-enabled
    expect(button).not.toBeDisabled();
  });

  test('handles scanning failure and shows error toast', async () => {
    axios.get.mockResolvedValueOnce({ data: { total_urls: 0, analysis: [] } });
    axios.post.mockRejectedValueOnce(new Error('Network error'));

    renderComponent();

    const input = screen.getByPlaceholderText(/https:\/\/example.com/i);
    fireEvent.change(input, { target: { value: 'https://bad.com' } });

    const button = screen.getByRole('button', { name: /Scan URL/i });
    fireEvent.click(button);

    await waitFor(() => expect(axios.post).toHaveBeenCalled());

    expect(toast.error).toHaveBeenCalledWith('Scanning failed. Check server connection.');
    expect(button).not.toBeDisabled();
  });

  test('shows phishing result and error toast', async () => {
    axios.get.mockResolvedValueOnce({ data: { total_urls: 0, analysis: [] } });
    axios.post.mockResolvedValueOnce({
      data: { is_phishing: true, url: 'https://bad.com', reason: 'Phishing detected' }
    });

    renderComponent();

    const input = screen.getByPlaceholderText(/https:\/\/example.com/i);
    fireEvent.change(input, { target: { value: 'https://bad.com' } });

    const button = screen.getByRole('button', { name: /Scan URL/i });
    fireEvent.click(button);

    await waitFor(() => expect(axios.post).toHaveBeenCalled());

    expect(toast.error).toHaveBeenCalledWith('Malicious Domain Detected!');

    expect(screen.getByText(/Phishing Detected/i)).toBeInTheDocument();
    expect(screen.getByText('https://bad.com')).toBeInTheDocument();
    expect(screen.getByText('Phishing detected')).toBeInTheDocument();
  });

  test('does not scan when URL input is empty', () => {
    axios.get.mockResolvedValueOnce({ data: { total_urls: 0, analysis: [] } });
    renderComponent();

    const button = screen.getByRole('button', { name: /Scan URL/i });
    fireEvent.click(button);

    expect(toast.error).toHaveBeenCalledWith('Please enter a URL first');
    expect(axios.post).not.toHaveBeenCalled();
  });
});