import { Routes, Route } from 'react-router-dom';
import Header from './components-old/Header.jsx';
import Home from './components-old/Home.jsx';
// import About from './components-old/About.jsx';
import Contact from './components-old/Contact.jsx';
// import Education from './components-old/Education.jsx';
// import Services from './components-old/Services.jsx';
// import Projects from './components-old/Projects.jsx';

const MainRouter = () => {
  return (
    <>
      <Header />
      <Routes>
        <Route path="/" element={<Home />} />
        {/* <Route path="/about" element={<About />} /> */}
        <Route path="/contact" element={<Contact />} />
        {/* <Route path="/education" element={<Education />} /> */}
        {/* <Route path="/services" element={<Services />} /> */}
        {/* <Route path="/projects" element={<Projects />} /> */}
      </Routes>
    </>
  )
}

export default MainRouter;