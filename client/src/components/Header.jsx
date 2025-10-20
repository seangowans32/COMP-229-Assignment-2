import { Link } from 'react-router-dom';

export default function Header() {
  return(
    <>
      <header className="header">
        <div className="container">
          <nav className="flex gap-20">
            <span className="logo">SG</span>
            <Link to="/">Home</Link>
            <Link to="/about">About</Link>
            <Link to="/services">Services</Link>
            <Link to="/projects">Projects</Link>
            <Link to="/education">Education</Link>
            <Link to="/contact">Contact</Link>
          </nav>
        </div>
      </header>
    </>
  );
}