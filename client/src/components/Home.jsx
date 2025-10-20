import AOS from 'aos';
import 'aos/dist/aos.css';
import { useEffect } from 'react';
import './Home.css';
import bannerImg from '../assets/img-2.jpg';
import introImg from '../assets/img-4.jpg';
import missionImg from '../assets/img-7.jpg';
import Footer from './Footer.jsx';

export default function Home() {
  // Years of Experience Calculation
  const yearStart = new Date(2018, 10, 1);
  const currentDate = new Date(Date.now());
  const yearsOfExperience = currentDate.getFullYear() - yearStart.getFullYear();

  // AOS Animations
  useEffect(() => {
    AOS.init();
  }, []);

  return(
    <>
      <section className="banner img-container">
        <img src={bannerImg} alt="banner" />
        <div className="container">
          <h1 data-aos="zoom-in" data-aos-duration="1000">Sean Gowans</h1>
          <h2 data-aos="zoom-in" data-aos-duration="2000">Front-End Web Developer Based In Germany</h2>
        </div>
      </section>

      <section className="intro">
        <div className="container" data-aos="zoom-in" data-aos-duration="1000">
          <h2>Introduction</h2>

          <div className="flex gap-40">
            <div className="img-container" data-aos="fade-up" data-aos-duration="1000">
              <img src={introImg} alt="intro"/>
            </div>

            <div className="content" data-aos="fade-up" data-aos-duration="1000">
              <p>Welcome to my portfolio! My name is Sean Gowans, and I am a web developer and software engineering student with over {yearsOfExperience} years of professional experience. Originally from Canada and now based in Germany, I've been fortunate to collaborate with clients across the globe — most notably an Australian company where I've independently delivered more than 50 projects since 2018. My work ranges from custom WordPress theme development to WooCommerce eCommerce builds, as well as front-end and back-end programming. Each project has given me the opportunity to blend technical expertise with creativity, delivering solutions that not only look great but also perform reliably.</p>
              <p>My mission is to continue learning by doing, adapting quickly, and delivering high-quality code that helps businesses thrive. Whether it’s a custom WordPress theme, an eCommerce solution, or a React-powered app, I bring discipline, creativity, and reliability to every project.</p>
              <a className="button" href="about">Learn More</a>
            </div>
          </div>
        </div>
      </section>

      <section className="mission-statement">
        <div className="container">
          <h2 data-aos="zoom-in" data-aos-duration="1000">My Mission</h2>

          <div className="flex  gap-40" data-aos="fade-up" data-aos-duration="1000">
            <div className="content" data-aos="fade-up" data-aos-duration="1000">
              <p>My mission is simple: to create meaningful digital experiences that empower businesses and individuals to grow. I thrive on challenges that push me to adapt, learn quickly, and step outside my comfort zone. Whether it’s developing a custom eCommerce site, coding a responsive front end in React, or experimenting with emerging technologies like Unreal Engine, I approach every task with curiosity, discipline, and dedication. As I continue my academic journey in software engineering while working full time, my focus remains on growing as a developer who not only writes clean, efficient code but also creates tools that make a real difference.</p>
              <a className="button" href="about">Learn More</a>
            </div>

            <div className="img-container" data-aos="fade-up" data-aos-duration="1000">
              <img src={missionImg} alt="mission"/>
            </div>
          </div>
        </div>
      </section>

      <Footer />
    </>
  );
}