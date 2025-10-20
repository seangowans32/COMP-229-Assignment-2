import { useState, useEffect, useRef } from 'react';

// Timer Hook - Experience Counter
export const useTimer = (startDate = new Date(2018, 10, 1, 0, 0, 0, 0)) => {
  const [timeElapsed, setTimeElapsed] = useState('');

  useEffect(() => {
    const startStamp = startDate.getTime();

    const updateClock = () => {
      const newDate = new Date();
      const newStamp = newDate.getTime();
      const diff = Math.round((newStamp - startStamp) / 1000);

      const d = Math.floor(diff / (24 * 60 * 60));
      const remainingAfterDays = diff - (d * 24 * 60 * 60);
      const h = Math.floor(remainingAfterDays / (60 * 60));
      const remainingAfterHours = remainingAfterDays - (h * 60 * 60);
      const m = Math.floor(remainingAfterHours / 60);
      const s = remainingAfterHours - (m * 60);

      setTimeElapsed(`${d} DAYS, ${h} HOURS, ${m} MINUTES, ${s} SECONDS OF EXPERIENCE`);
    };

    updateClock(); // Initial call
    const timer = setInterval(updateClock, 1000);

    return () => clearInterval(timer);
  }, [startDate]);

  return timeElapsed;
};

// Scroll Hook - Header scroll effects
export const useScroll = () => {
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 1);
    };

    window.addEventListener('scroll', handleScroll);
    handleScroll(); // Check initial state

    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return isScrolled;
};