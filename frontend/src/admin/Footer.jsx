import { Footer } from 'flowbite-react';
import { Link } from 'react-router-dom';
import { BsFacebook, BsInstagram, BsTwitter, BsGithub, BsDribbble } from 'react-icons/bs';
import BlogLogo from '../assets/logo.jpg';

export default function FooterCom() {
  return (
    <Footer container className='border border-t-4 border-gray-300'>
      <div className='w-full max-w-7xl mx-auto'>
        {/* Hide the main footer content on mobile */}
        <div className='hidden sm:block'>
          <div className='grid w-full justify-between sm:flex md:grid-cols-1'>
            <div className="container mx-auto flex items-center justify-between ">
              {/* Blog Image and Name as Link */}
              <Link to="/" className="flex items-center">
                <img
                  src={BlogLogo}
                  alt="Jamal's Blog Logo"
                  className="h-12 w-12  mr-4"
                />
                <h1 className="text-sm sm:text-xl font-semibold dark:text-white">Jamal's Auth</h1>
              </Link>
            </div>
            <div className='grid grid-cols-2 gap-8 mt-4 sm:grid-cols-3 sm:gap-6'>
              <div>
                <Footer.Title title='About' />
                <Footer.LinkGroup col>
                  <Footer.Link
                    href='/contact'
                  >
                    Contact
                  </Footer.Link>
                  <Footer.Link
                    href='/'
                  >
                    Jamal's Auth
                  </Footer.Link>
                </Footer.LinkGroup>
              </div>
              <div>
                <Footer.Title title='Follow us' />
                <Footer.LinkGroup col>
                  <Footer.Link
                    href='https://www.github.com/APSALJAMAL'
                    target='_blank'
                    rel='noopener noreferrer'
                  >
                    Github
                  </Footer.Link>
                  <Footer.Link href='#'>Discord</Footer.Link>
                </Footer.LinkGroup>
              </div>
              <div>
                <Footer.Title title='Legal' />
                <Footer.LinkGroup col>
                  <Footer.Link href='/policy'>Privacy Policy</Footer.Link>
                  <Footer.Link href='/terms'>Terms &amp; Conditions</Footer.Link>
                </Footer.LinkGroup>
              </div>
            </div>
          </div>
          <Footer.Divider />
        </div>
        
        {/* Always show the copyright section */}
        <div className='w-full flex flex-col  items-center sm:flex-row mb-10 sm:justify-between'>
          <Footer.Copyright
            href='#'
            by="Jamal's Company"
            year={new Date().getFullYear()}
          />
          {/* Social icons hidden on mobile */}
          <div className=" gap-6 mt-4 sm:mt-0 sm:justify-center hidden sm:flex">
            <Footer.Icon href='#' icon={BsFacebook}/>
            <Footer.Icon href='#' icon={BsInstagram}/>
            <Footer.Icon href='#' icon={BsTwitter}/>
            <Footer.Icon href='#' icon={BsGithub}/>
            <Footer.Icon href='#' icon={BsDribbble}/>
          </div>
        </div>
      </div>
    </Footer>
  );
}
