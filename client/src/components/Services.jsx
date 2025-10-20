import AOS from 'aos';
import 'aos/dist/aos.css';
import { useEffect } from 'react';
import './Services.css';
import bannerImg from '../assets/img-9.jpg';
import Footer from './Footer.jsx';
import wordpressImg from '../assets/wp.jpg';
import frontendImg from '../assets/front-end.jpg';
import backendImg from '../assets/back-end.jpg';
import uiuxImg from '../assets/ux.png';
import aiImg from '../assets/ai.jpg';

export default function Services() {
  // AOS Animations
  useEffect(() => {
    AOS.init();
  }, []);

  return(
    <>
      <section className="banner img-container">
        <img src={bannerImg} alt="banner"/>
        <div className="container">
          <h1 data-aos="zoom-in" data-aos-duration="1000">Services</h1>
        </div>
      </section>

      <section className="services">
        <div className="container">
          <h2 data-aos="fade-up" data-aos-duration="1000">What I Offer</h2>
          
          <div className="services-grid flex gap-20">
            <div className="service-item" data-aos="fade-up" data-aos-duration="1000" data-aos-delay="100">
              <div className="img-container">
                <img src={wordpressImg} alt="Custom WordPress Development"/>
              </div>
              <h3>1. Custom WordPress Development</h3>
              <ul>
                <li>Building fully tailored WordPress themes from scratch</li>
                <li>Clean, optimized, and responsive code for any industry</li>
                <li>Easy-to-manage backend for clients</li>
              </ul>
            </div>

            <div className="service-item" data-aos="fade-up" data-aos-duration="1000" data-aos-delay="200">
            <div className="img-container">
                <img src={frontendImg} alt="Frontend Web Development"/>
              </div>
              <h3>2. Frontend Web Development</h3>
              <ul>
                <li>Creating modern, responsive websites using HTML, CSS/SCSS, JavaScript</li>
                <li>Pixel-perfect layouts with smooth interactions</li>
                <li>Focus on usability and performance</li>
              </ul>
            </div>

            <div className="service-item" data-aos="fade-up" data-aos-duration="1000" data-aos-delay="300">
              <div className="img-container">
                <img src={backendImg} alt="Backend Development"/>
              </div>
              <h3>3. Backend Development</h3>
              <ul>
                <li>PHP development for WordPress and custom functionality</li>
                <li>Experience with Java, C#, and server-side logic</li>
                <li>Clean architecture and scalable solutions</li>
              </ul>
            </div>

            <div className="service-item" data-aos="fade-up" data-aos-duration="1000" data-aos-delay="400">
              <div className="img-container">
                <img src={uiuxImg} alt="UI/UX Implementation"/>
              </div>
              <h3>4. UI/UX Implementation</h3>
              <ul>
                <li>Translating designs into functional web pages</li>
                <li>Ensuring accessibility, responsive design, and smooth navigation</li>
                <li>Bringing client ideas to life visually and functionally</li>
              </ul>
            </div>

            <div className="service-item" data-aos="fade-up" data-aos-duration="1000" data-aos-delay="500">
              <div className="img-container">
                <img src={aiImg} alt="Emerging Skills & Technologies"/>
              </div>
              <h3>5. Emerging Skills & Technologies</h3>
              <ul>
                <li>Growing expertise in React, C#, Java, Unreal Engine</li>
                <li>Exploring software engineering and interactive applications</li>
                <li>Continuous learning to stay ahead of trends</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <Footer />
    </>
  );
}