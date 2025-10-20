import AOS from 'aos';
import 'aos/dist/aos.css';
import { useEffect } from 'react';
import './Education.css';
import bannerImg from '../assets/img-8.jpg';
import Footer from './Footer.jsx';

export default function Education() {
  // AOS Animations
  useEffect(() => {
    AOS.init();
  }, []);

  return(
    <>
      <section className="banner img-container">
        <img src={bannerImg} alt="banner"/>
        <div className="container">
          <h1 data-aos="zoom-in" data-aos-duration="1000">Education</h1>
        </div>
      </section>

      <section className="education">
        <div className="container">
          <h2 data-aos="zoom-in" data-aos-duration="1000">Education & Professional Qualifications</h2>

          <div className="timeline flex gap-20">
            <div className="timeline-item" data-aos="zoom-in" data-aos-duration="1000">
              <h3>Education: 2025 - Current</h3>

              <ul>
                <li>Advanced Diploma in Software Engineering</li>
                <li>Centennial College, Toronto, Canada</li>
                <li>Currently in 3rd semester of 6.</li>
                <li>Coursework includes: React, Java, C#, Unreal Engine, database systems, and software architecture.</li>
                <li>Learning both front-end and back-end development, expanding beyond CMS work into full-stack engineering.</li>
                <li>Balancing full-time study with professional web development to strengthen both theoretical and practical skills.</li>
              </ul>
            </div>

            <div className="timeline-item" data-aos="zoom-in" data-aos-duration="1000">
              <h3>Professional Qualification: 2018 - Current</h3>

              <ul>
                <li>Web Development (Self-Taught & Industry Experience)</li>
                <li>Working as a Web Developer at <a href="https://thriveweb.com.au/" target="_blank" rel="noopener">Thrive Digital</a> (Remote - Australia)</li>
                <li>Over 50 custom WordPress projects delivered</li>
                <li>Specialized in PHP, JavaScript, jQuery, CSS/SCSS, and Git</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <Footer />
    </>
  );
}