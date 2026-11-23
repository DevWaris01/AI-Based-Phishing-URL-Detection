import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Pishing_domain from '../Frontend/src/pages/Pishing_domain.jsx';
import axios from 'axios';
import toast from 'react-hot-toast';

jest.mock('axios');
jest.mock('react-hot-toast', () => ({
  error: jest.fn(),
  success: jest.fn(),
}));

describe('Pishing_domain component', () => {
  const mockLiveData = {
    total_urls: 2,
    analysis: [
      { url: 'https://phish1.com', reason: 'Suspicious login page' },
      { url: 'https://phish2.com', reason: 'Fake banking site' },
    ],
  };

  beforeEach(() => {
    jest.clearAllMocks();
    axios.get.mockResolvedValue({ data: mockLiveData });
  });

  test('renders live threats list correctly', async () => {
    render(<Pishing_domain />);
    // Wait for live data fetch
    await waitFor(() => expect(axios.get).toHaveBeenCalledTimes(1));
    // Check total monitored count
    expect(screen.getByText(/Total Monitored: 2/i)).toBeInTheDocument();
    // Check each threat item
    mockLiveData.analysis.forEach((item) => {
      expect(screen.getByText(item.url)).toBeInTheDocument();
      const link = screen.getByRole('link', { name: '' });
      expect(link).toHaveAttribute('href', item.url);
    });
    // Check analysis report reason
    expect(screen.getByText(mockLiveData.analysis[0].reason)).toBeInTheDocument();
  });

  test('shows loading spinner while fetching live data', async () => {
    axios.get.mockImplementation(() => new Promise(() => {})); // never resolves
    render(<Pishing_domain />);
    expect(screen.getByRole('img', { hidden: true })).toBeInTheDocument(); // Loader2 has role img
  });

  test('handles scan URL success (safe domain)', async () => {
    const safeResponse = { is_phishing: false, url: 'https://safe.com', reason: 'No issues' };
    axios.post.mockResolvedValue({ data: safeResponse });

    render(<Pishing_domain />);
    const input = screen.getByPlaceholderText(/https:\/\/example.com/i);
    fireEvent.change(input, { target: { value: 'https://safe.com' } });
    fireEvent.click(screen.getByRole('button', { name: /Scan URL/i }));

    await waitFor(() => expect(axios.post).toHaveBeenCalledTimes(1));
    expect(toast.success).toHaveBeenCalledWith('Domain appears to be safe.');
    expect(screen.getByText('Safe Domain')).toBeInTheDocument();
    expect(screen.getByText(safeResponse.url)).toBeInTheDocument();
  });

  test('handles scan URL success (phishing domain)', async () => {
    const phishingResponse = { is_phishing: true, url: 'https://phish.com', reason: 'Malicious content' };
    axios.post.mockResolvedValue({ data: phishingResponse });

    render(<Pishing_domain />);
    const input = screen.getByPlaceholderText(/https:\/\/example.com/i);
    fireEvent.change(input, { target: { value: 'https://phish.com' } });
    fireEvent.click(screen.getByRole('button', { name: /Scan URL/i }));

    await waitFor(() => expect(axios.post).toHaveBeenCalledTimes(1));
    expect(toast.error).toHaveBeenCalledWith('Malicious Domain Detected!');
    expect(screen.getByText('Phishing Detected')).toBeInTheDocument();
    expect(screen.getByText(phishingResponse.url)).toBeInTheDocument();
  });

  test('shows error toast when scanning fails', async () => {
    axios.post.mockRejectedValue(new Error('Network error'));

    render(<Pishing_domain />);
    const input = screen.getByPlaceholderText(/https:\/\/example.com/i);
    fireEvent.change(input, { target: { value: 'https://error.com' } });
    fireEvent.click(screen.getByRole('button', { name: /Scan URL/i }));

    await waitFor(() => expect(axios.post).toHaveBeenCalledTimes(1));
    expect(toast.error).toHaveBeenCalledWith('Scanning failed. Check server connection.');
  });

  test('does not scan when URL input is empty', async () => {
    render(<Pishing_domain />);
    fireEvent.click(screen.getByRole('button', { name: /Scan URL/i }));
    expect(toast.error).toHaveBeenCalledWith('Please enter a URL first');
    expect(axios.post).not.toHaveBeenCalled();
  });
});