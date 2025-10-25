import AOS from 'aos';
import 'aos/dist/aos.css';
import { useEffect } from 'react';
import './Home.css';

// import bannerImg from '../assets/img-2.jpg';
// import introImg from '../assets/img-4.jpg';
// import missionImg from '../assets/img-7.jpg';
// import Footer from './Footer.jsx';


import BodyCalculator from './components/BodyCalculator.jsx';
import RegistrationForm from './components/RegistrationForm.jsx';
import LoginForm from './components/LoginForm.jsx';
import History from './components/History.jsx';

import Footer from './Footer.jsx';

export default function Home() {
  // Years of Experience Calculation
  // const yearStart = new Date(2018, 10, 1);
  // const currentDate = new Date(Date.now());
  // const yearsOfExperience = currentDate.getFullYear() - yearStart.getFullYear();

  // AOS Animations
  useEffect(() => {
    AOS.init();
  }, []);

  return(
    <>
      <div className="App">
        <div className="App-body">
          <div className='container'>
            <BodyCalculator />
            {/* <RegistrationForm /> */}
            {/* <LoginForm /> */}
            {/* <History /> */}
            {/* <Footer /> */}
          </div>
        </div>
      </div>
    </>
  );
}