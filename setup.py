import os

import setuptools

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.md')).read()

setuptools.setup(
    name='django-jwt-oidc',
    version=os.getenv('PACKAGE_VERSION').split('/')[-1],
    packages=setuptools.find_packages(),
    include_package_data=True,
    description='Django library that implements the authentification for OpenId SSO with JWT from oauth2.',
    long_description=README,
    long_description_content_type="text/markdown",
    author='Arnau Casas Saez',
    author_email='casassarnau@gmail.com',  # SEE NOTE BELOW (*)
    url='https://github.com/Casassarnau/django-jwt',
    license='MIT',
    python_requires='>=3.6',
    project_urls={
        "Bug Tracker": "https://github.com/Casassarnau/django-jwt/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'django>=2.2',
        'pycryptodome',
        'jwcrypto',
        'urllib3'
    ]
)

# (*) Please direct queries to the discussion group, rather than to me directly
#     Doing so helps ensure your question is helpful to other users.
#     Queries directly to my email are likely to receive a canned response.
#
#     Many thanks for your understanding.
