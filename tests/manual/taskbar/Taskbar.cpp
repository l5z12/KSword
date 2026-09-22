#include "Taskbar.h"
#include "SpectrumWidget.h"
#include "AudioAnalyze.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QPushButton>
#include <QDebug>

Taskbar::Taskbar(QWidget* parent) : QMainWindow(parent)
{
    // Simplest window setup.
    setWindowTitle("Spectrum Display");
    setFixedSize(800, 100);

    // Create central widget
    QWidget* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // Create layout
    QHBoxLayout* layout = new QHBoxLayout(centralWidget);
    layout->setContentsMargins(10, 10, 10, 10);

    // Create spectrum display component
    m_spectrumWidget = new SpectrumWidget(this);
    spectrumWidget_->setMinimumSize(600, 60);
    layout->addWidget(spectrumWidget_);

    // Add exit button
    QPushButton* exitBtn = new QPushButton("Exit", this);
    exitBtn->setFixedSize(60, 30);
    connect(exitBtn, &QPushButton::clicked, this, &QMainWindow::close);
    layout->addWidget(exitBtn);

    // initialize audio analyzer
    analyzer_ = new AudioSpectrumAnalyzer(this);

    if (analyzer_->initialize()) {
        bool connected = connect(analyzer_, &AudioSpectrumAnalyzer::spectrumDataReady,
            spectrumWidget_, &SpectrumWidget::setSpectrumData);

        qDebug() << "Spectrum signal connected:" << connected;

        if (connected) {
            analyzer_->startCapture();
        }
    }

    // Start spectrum animation
    spectrumWidget_->startAnimation(30);
    qDebug() << "Simple spectrum display started";
}

Taskbar::~Taskbar()
{
    if (analyzer_) {
        analyzer_->stopCapture();
    }
}
