import AOS from 'aos';
import 'aos/dist/aos.css';
import { useEffect } from 'react';
import './Projects.css';
import bannerImg from '../assets/img-3.jpg';
import samadhiImage from '../assets/samadhi.png';
import keystoneImage from '../assets/keystone.png';
import cdaClinicsImage from '../assets/cdaclinics.png';
import wsxVideo from '../assets/wsx-video.mp4';
import zero9Video from '../assets/zero9.mp4';
import miboImage from '../assets/mibo.png';
import Footer from './Footer.jsx';

export default function Projects() {
  // AOS Animations
  useEffect(() => {
    AOS.init();
  }, []);

  return(
    <>
      <section className="banner img-container">
        <img src={bannerImg} alt="banner"/>
        <div className="container">
          <h1 data-aos="zoom-in" data-aos-duration="1000">Projects</h1>
        </div>
      </section>

      <section className="featured-projects">
        <div className="container">
          <h2 data-aos="zoom-in" data-aos-duration="1000">Featured Projects</h2>

          <div className="flex gap-20">
            <div className="project-box" data-aos="zoom-in" data-aos-duration="1000" data-aos-delay="100">
              <div className="img-container">
                <video className="banner-video" autoPlay={1} muted loop data-src={zero9Video}>
                  <source src={zero9Video} type="video/mp4"/>
                </video>
              </div>
              <ul className="flex gap-10">
                <li>WordPress</li>
                <li>PHP</li>
                <li>HTML5</li>
                <li>JS</li>
                <li>CSS3 + SCSS</li>
              </ul>

              <p>Developed a custom WordPress theme with responsive layouts and performance optimization, providing the client with a modern and reliable online presence.</p>
              <a className="button" href="https://zero9.com.au/" target="_blank" rel="noopener">Visit Site</a>
            </div>

            <div className="project-box" data-aos="zoom-in" data-aos-duration="1000" data-aos-delay="200">
              <div className="img-container">
                <img src={samadhiImage} alt="Samadhi Builds project image"/>
              </div>
              <ul className="flex gap-10">
                <li>WordPress</li>
                <li>PHP</li>
                <li>HTML5</li>
                <li>JS</li>
                <li>CSS3 + SCSS</li>
              </ul>

              <p>Built a personalized WordPress portfolio site featuring clean navigation and fast loading speeds, allowing the client to showcase their work effectively.</p>
              <a className="button" href="https://samadhibuilds.com.au/" target="_blank" rel="noopener">Visit Site</a>
            </div>

            <div className="project-box" data-aos="zoom-in" data-aos-duration="1000" data-aos-delay="300">
              <div className="img-container">
                <img src={keystoneImage} alt="Keystone Negotiation project image"/>
              </div>
              <ul className="flex gap-10">
                <li>WordPress</li>
                <li>PHP</li>
                <li>HTML5</li>
                <li>JS</li>
                <li>CSS3 + SCSS</li>
              </ul>

              <p>Created a professional WordPress theme with custom templates and branding support, making it easy for the client to manage and update content.</p>
              <a className="button" href="https://www.keystonenegotiation.com/" target="_blank" rel="noopener">Visit Site</a>
            </div>

            <div className="project-box" data-aos="zoom-in" data-aos-duration="1000" data-aos-delay="400">
              <div className="img-container">
                <img src={cdaClinicsImage} alt="CDA Clinics project image"/>
              </div>
              <ul className="flex gap-10">
                <li>WordPress</li>
                <li>PHP</li>
                <li>HTML5</li>
                <li>JS</li>
                <li>CSS3 + SCSS</li>
              </ul>

              <p>Designed and developed a WordPress site tailored to a service-based business, focusing on usability, mobile responsiveness, and clear calls to action.</p>
              <a className="button" href="https://cdaclinics.com.au/" target="_blank" rel="noopener">Visit Site</a>
            </div>

            <div className="project-box" data-aos="zoom-in" data-aos-duration="1000" data-aos-delay="500">
              <div className="img-container">
                <video className="banner-video" autoPlay={1} muted loop data-src={wsxVideo}>
                  <source src={wsxVideo} type="video/mp4"/>
                </video>
              </div>
              <ul className="flex gap-10">
                <li>WordPress</li>
                <li>PHP</li>
                <li>HTML5</li>
                <li>JS</li>
                <li>CSS3 + SCSS</li>
              </ul>

              <p>Built a WordPress-powered blog with custom styling and a user-friendly backend, enabling the client to publish and manage articles effortlessly.</p>
              <a className="button" href="https://wsxchampionship.com/" target="_blank" rel="noopener">Visit Site</a>
            </div>

            <div className="project-box" data-aos="zoom-in" data-aos-duration="1000" data-aos-delay="600">
              <div className="img-container">
                <img src={miboImage} alt="Mibo project image"/>
              </div>
              <ul className="flex gap-10">
                <li>WordPress</li>
                <li>PHP</li>
                <li>HTML5</li>
                <li>JS</li>
                <li>CSS3 + SCSS</li>
              </ul>

              <p>Delivered a fully custom WordPress theme for an agency, with a clean design and flexible content sections to support future growth and updates.</p>
              <a className="button" href="https://www.mibowork.com.au/" target="_blank" rel="noopener">Visit Site</a>
            </div>
          </div>
        </div>
      </section>

      <section className="sites">
        <div className="container">
          <h2 data-aos="zoom-in" data-aos-duration="1000">Take a look at my full list of projects</h2>

          <ul className="flex gap-10" data-aos="fade-up" data-aos-duration="1000">
            <li><a href="https://tweedvalleywaterbores.com.au/" target="_blank" rel="noopener">Tweed Valley</a></li>
            <li><a href="https://transformushealth.com.au/" target="_blank" rel="noopener">Transformus Health</a></li>
            <li><a href="https://toowoombarugs.com.au/" target="_blank" rel="noopener">Toowoomba Rugs</a></li>
            <li><a href="https://sitepsm.com.au/" target="_blank" rel="noopener">Site PSM</a></li>
            <li><a href="https://southportlodge.com.au/" target="_blank" rel="noopener">Southport Lodge</a></li>
            <li><a href="https://soundaviary.com/" target="_blank" rel="noopener">Soundaviary</a></li>
            <li><a href="https://samadhibuilds.com.au/" target="_blank" rel="noopener">Samadhi Builds</a></li>
            <li><a href="https://resorthomes.com.au/" target="_blank" rel="noopener">Resort Homes</a></li>
            <li><a href="https://regionalfutures.net.au/" target="_blank" rel="noopener">Regional Futures</a></li>
            <li><a href="https://redmangallpsychologists.com.au/" target="_blank" rel="noopener">Redman Gall Psychologists</a></li>
            <li><a href="https://yourpropertyteam.com.au/" target="_blank" rel="noopener">Your Property Team</a></li>
            <li><a href="https://premiersalon.com.au/" target="_blank" rel="noopener">Premier Salon Supplies</a></li>
            <li><a href="https://leisurepools.eu/" target="_blank" rel="noopener">Leisure Pools</a></li>
            <li><a href="https://pmsolutionsaustralia.com.au/" target="_blank" rel="noopener">PM Solutions Australia</a></li>
            <li><a href="https://pimpamadental.com.au/" target="_blank" rel="noopener">Pimpama Dental</a></li>
            {/* <!-- <li><a href="http://payvantage.c.thrivex.io/" target="_blank" rel="noopener">Pay Vantage</a></li> --> */}
            <li><a href="https://paletterestaurant.com.au/" target="_blank" rel="noopener">Palette Restaurant</a></li>
            <li><a href="https://nomeservices.com.au/" target="_blank" rel="noopener">Nome Services</a></li>
            <li><a href="https://drnambajra.au/" target="_blank" rel="noopener">Dr Nam Bajra</a></li>
            <li><a href="https://rgsenv.com/" target="_blank" rel="noopener">RGSENV</a></li>
            {/* <!-- <li><a href="https://loftuspeak.neo.7hriv3.com/" target="_blank" rel="noopener">Loftus Peak</a></li> --> */}
            <li><a href="https://thelanguageacademy.com.au/" target="_blank" rel="noopener">The Language Academy</a></li>
            <li><a href="https://integratanks.com/" target="_blank" rel="noopener">Integra Tanks</a></li>
            {/* <!-- <li><a href="http://hotelphones.c.thrivex.io/" target="_blank" rel="noopener">Hotel Phones</a></li> --> */}
            <li><a href="http://glassstudios.com.au/" target="_blank" rel="noopener">Glass Studios</a></li>
            <li><a href="https://commercialglassaustralia.com.au/" target="_blank" rel="noopener">Commercial Glass</a></li>
            {/* <!-- <li><a href="http://gcrconstruction.neo.7hriv3.com/" target="_blank" rel="noopener">GCR Construction</a></li> --> */}
            <li><a href="http://gcmedical.net.au/" target="_blank" rel="noopener">GC Medical</a></li>
            <li><a href="https://fortunepartners.com.au/" target="_blank" rel="noopener">Fortune Partners</a></li>
            {/* <!-- <li><a href="https://farnorth.c.thrivex.io/" target="_blank" rel="noopener">Far North</a></li> --> */}
            <li><a href="https://theexhibitionistbar.com.au/" target="_blank" rel="noopener">The Exhibitionist Bar</a></li>
            <li><a href="https://esteemdentalcare.com.au/" target="_blank" rel="noopener">Esteem Dental Care</a></li>
            <li><a href="https://dsllaw.com.au/" target="_blank" rel="noopener">DSL Law</a></li>
            {/* <!-- <li><a href="http://distillingalife.c.thrivex.io/" target="_blank" rel="noopener">Distilling A Life</a></li> --> */}
            {/* <!-- <li><a href="http://pms.c.thrivex.io/" target="_blank" rel="noopener">PMS</a></li> --> */}
            <li><a href="https://disparu.com.au/" target="_blank" rel="noopener">Disparu</a></li>
            <li><a href="https://daveyconstructions.com/" target="_blank" rel="noopener">Davey Constructions</a></li>
            <li><a href="https://cdaclinics.com.au/" target="_blank" rel="noopener">CDA Clinics</a></li>
            <li><a href="https://burleighleagues.com.au/" target="_blank" rel="noopener">Burleigh Bears</a></li>
            <li><a href="https://baysidefamilydentist.com.au/" target="_blank" rel="noopener">Bayside Family Dentist</a></li>
            {/* <!-- <li><a href="http://backstreetguides.c.thrivex.io/" target="_blank" rel="noopener">Back Street Guides</a></li> --> */}
            <li><a href="https://ausships.com/" target="_blank" rel="noopener">AUS Ships</a></li>
            <li><a href="http://aurora.edu.au/" target="_blank" rel="noopener">Aurora</a></li>
            <li><a href="https://pittaccountants.com/" target="_blank" rel="noopener">Pitt Accountants</a></li>
            {/* <!-- <li><a href="http://abilityabroad.c.thrivex.io/" target="_blank" rel="noopener">Ability Abroad</a></li> --> */}
            <li><a href="https://wsxchampionship.com/" target="_blank" rel="noopener">WSX Championship</a></li>
            <li><a href="https://dentistdirect.au/" target="_blank" rel="noopener">Dentist Direct</a></li>
            {/* <!-- <li><a href="https://designaustralia.z.thrivex.io/" target="_blank" rel="noopener">Design Australia</a></li> --> */}
            <li><a href="https://blacklinesteel.com.au/" target="_blank" rel="noopener">Blackline Steel</a></li>
            {/* <!-- <li><a href="http://mjtradingcards.u.thrivex.io/" target="_blank" rel="noopener">MJ Trading Cards</a></li> --> */}
            <li><a href="https://truewater.com.au/" target="_blank" rel="noopener">True Water</a></li>
            <li><a href="https://history.atsils.org.au/" target="_blank" rel="noopener">Atsils</a></li>
            <li><a href="https://oreillysvineyard.com.au/" target="_blank" rel="noopener">Oreillys Vineyard</a></li>
            <li><a href="https://koolbeanz.com.au/" target="_blank" rel="noopener">Kool Beanz</a></li>
            <li><a href="https://lionshaven.com.au/" target="_blank" rel="noopener">Lions Haven</a></li>
            <li><a href="https://proyacht.com.au/" target="_blank" rel="noopener">Proyacht</a></li>
            <li><a href="https://turnstonecollective.com.au/" target="_blank" rel="noopener">Turnstone Collective</a></li>
            <li><a href="https://windowlineqld.com.au/" target="_blank" rel="noopener">Windowline</a></li>
            <li><a href="https://zero9.com.au/" target="_blank" rel="noopener">Zero9</a></li>
            {/* <!-- <li><a href="https://driveredace.a.thrivex.io/" target="_blank" rel="noopener">Driver ED ACE</a></li> --> */}
            <li><a href="https://evnv.com.au/" target="_blank" rel="noopener">EVNV</a></li>
            {/* <!-- <li><a href="https://evnvfullsite.a.thrivex.io/" target="_blank" rel="noopener">EVNV</a></li> --> */}
            <li><a href="https://www.keystonenegotiation.com/" target="_blank" rel="noopener">Keystone Negotiation</a></li>
            <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">Mibo</a></li>
            {/* <!-- <li><a href="https://aivl.a.thrivex.io/" target="_blank" rel="noopener">Aivl</a></li> --> */}

            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">Warwick</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">bayline-electrical</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">cooling-tower-solutions</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">coulson-operations</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">douglasdevelopment</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">driveredace</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">evnv</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">happylearners</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">highfields</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">kool-beanz</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">lewisautocar</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">marqmee</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">NECSG</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">orbwiz</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">resource-hub</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">seegroup</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">skypeakcapital</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">surfschool</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">surreyhouse</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">triple-a-full-site</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">triplea</a></li> */}
            {/* <li><a href="https://www.mibowork.com.au/" target="_blank" rel="noopener">wickedstore</a></li> */}

            <li><a href="https://thebaratie.infinityfreeapp.com/" target="_blank" rel="noopener">The Baratie</a></li>
          </ul>
        </div>
      </section>

      <Footer />
    </>
  );
}