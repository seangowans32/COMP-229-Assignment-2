import React, { useEffect } from 'react';
import { useTimer, useScroll } from '../hooks/useCustomHooks';

// Component for managing all the effects
const EffectsManager = ({ children }) => {
  // Initialize all hooks
  const timeElapsed = useTimer();
  const isScrolled = useScroll();

  // Update header class based on scroll
  useEffect(() => {
    const header = document.querySelector('header');
    if (header) {
      if (isScrolled) {
        header.classList.add('scroll-active');
      } else {
        header.classList.remove('scroll-active');
      }
    }
  }, [isScrolled]);

  // Update time elapsed element if it exists
  useEffect(() => {
    const timeElement = document.getElementById('time-elapsed');
    if (timeElement && timeElapsed) {
      timeElement.innerHTML = timeElapsed;
    }
  }, [timeElapsed]);

  return (
    <>
      {children}
    </>
  );
};

// Component for the experience timer display
export const ExperienceTimer = () => {
  const timeElapsed = useTimer();
  
  return (
    <div id="time-elapsed">
      {timeElapsed}
    </div>
  );
};

export default EffectsManager;