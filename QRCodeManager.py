import cv2
import random
import qrcode

def readQRCode():
    cap = cv2.VideoCapture(0)
    detector = cv2.QRCodeDetector()
    data_list = []
    while True:
        _, img = cap.read()
        data, bbox, _ = detector.detectAndDecode(img)
        if bbox is not None and data:
            data_list.append(data)
            for i in range(len(bbox)):
                x, y = tuple(bbox[i][0])
                start = (int(x), int(y))
                w, h = tuple(bbox[i][2])
                end = (int(w), int(h))
                cv2.rectangle(img, start, end, color=(255, 0, 0), thickness=2)
            if len(data_list) == 5 and all(listed == data for listed in data_list):
                data_list = [random.random()]
                data_list = [random.random()]
                data_list = [random.random()]
                break
        cv2.imshow("img", img)
        if cv2.waitKey(1) == ord("q"):
            break
    cap.release()
    cv2.destroyAllWindows()
    return data.encode()

def generateQRCode(file: str, data: bytes):
    qr = qrcode.QRCode()
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image()
    img.save(file)