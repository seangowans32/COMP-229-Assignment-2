import AOS from 'aos';
import 'aos/dist/aos.css';
import { useEffect } from 'react';
import './About.css';
import bannerImg from '../assets/img-1.jpg';
import profileImg from '../assets/sean-gowans.png';
import resumePdf from '../assets/sean-gowans-cv24.pdf';
import Footer from './Footer.jsx';

export default function About() {
  // AOS Animations
  useEffect(() => {
    AOS.init();
  }, []);

  return(
    <>
      <section className="banner img-container">
        <img src={bannerImg} alt="banner"/>
        <div className="container">
          <h1 data-aos="zoom-in" data-aos-duration="1000">About Me</h1>
        </div>
      </section>

      <section className="about">
        <div className="container">
          <div className="flex gap-40">
            <div className="col-left">
              <div className="img-container">
                <img src={profileImg} alt="profile"/>
              </div>

              <a className="button" href={resumePdf} download>Download Resume</a>
            </div>

            <div className="content">
              <h3>Who I Am:</h3>
              <p>My name is Sean Gowans, and I’m a self-taught developer turned software engineering student. I began my professional journey in October 2018 when I started working full time as a remote web developer for a company based in Australia. From day one, I had to hit the ground running — no formal training, no one looking over my shoulder, just the drive to figure things out and deliver results. Over the years, I’ve built over 50 custom WordPress and WooCommerce projects, developing everything from scratch themes to advanced eCommerce platforms.</p>

              <h3>My Background & Work Ethic:</h3>
              <p>Working entirely remotely for an international company taught me discipline, accountability, and time management. It also exposed me to diverse clients, industries, and challenges, which pushed me to continuously evolve. I quickly realized that learning “on the go” was one of my greatest strengths. New problems didn’t intimidate me; they motivated me. If I didn’t know how to do something, I taught myself. If a new tool or language was required, I adapted. That mindset has carried me throughout my career and remains a defining trait of how I approach both work and education today.</p>

              <h3>Current Education:</h3>
              <p>I am currently in my third semester of a six-semester Advanced Diploma in Software Engineering. Balancing full-time study with full-time work means I’m no stranger to long days, often dedicating 16 hours to sharpening my skills, finishing coursework, and delivering projects. While it’s demanding, I see it as an investment in myself. My education gives me a strong foundation in areas like React, Java, C#, Unreal Engine, and modern software development practices — skills I’m eager to combine with my industry experience to open new opportunities in the future.</p>

              <h3>Technical Skills & Tools:</h3>
              <p>Over the years, I’ve mastered a wide range of technologies. On the web development side, I specialize in WordPress, WooCommerce, PHP, JavaScript, jQuery, CSS, and SCSS. More recently, I’ve been expanding into React, modern JavaScript frameworks, and backend development with Java and C#. I also have experience with Git for version control, ensuring clean collaboration and organized workflows. Beyond traditional web technologies, I’m exploring new frontiers like Unreal Engine, diving into interactive applications and game development to broaden my creative toolkit.</p>

              <h3>What Drives Me:</h3>
              <p>What keeps me motivated is the belief that every project is an opportunity to grow — both as a developer and as a person. I take pride in delivering reliable, high-quality solutions, but I also value creativity and curiosity. I enjoy problem-solving, thinking outside the box, and finding ways to make digital experiences both functional and engaging. Most importantly, I value hard work and persistence; my journey so far has proven that with enough dedication, you can achieve anything, even without a traditional start.</p>
            </div>
          </div>
        </div>
      </section>

      <Footer />
    </>
  );
}