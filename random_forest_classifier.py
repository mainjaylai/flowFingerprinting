import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer

def preprocess_data(data):
    # 处理缺失值
    imputer = SimpleImputer(strategy='mean')
    data_imputed = imputer.fit_transform(data)
    
    # 标准化特征
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(data_imputed)
    
    return data_scaled

def train_random_forest(X, y, n_classes, n_estimators=100):
    # 分割数据集
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 预处理数据
    X_train_processed = preprocess_data(X_train)
    X_test_processed = preprocess_data(X_test)
    
    # 训练随机森林模型
    rf_classifier = RandomForestClassifier(n_estimators=n_estimators, n_jobs=-1, random_state=42)
    rf_classifier.fit(X_train_processed, y_train)
    
    # 评估模型
    accuracy = rf_classifier.score(X_test_processed, y_test)
    print(f"模型准确率: {accuracy:.2f}")
    
    return rf_classifier

def main():
    # 加载数据
    # 注意: 您需要根据实际情况修改数据加载方式
    data = pd.read_csv('network_traffic_data.csv')
    
    # 提取特征和标签
    features = ['源IP', '目的IP', '源端口', '目的端口', '协议类型', '包大小', '时间戳', 'TTL', '标志位', '头部字段']
    X = data[features]
    y = data['类别']  # 假设您的数据集中有一个'类别'列
    
    # 将IP地址转换为数值
    X['源IP'] = X['源IP'].apply(lambda x: int(''.join([f"{int(i):03d}" for i in x.split('.')])))
    X['目的IP'] = X['目的IP'].apply(lambda x: int(''.join([f"{int(i):03d}" for i in x.split('.')])))
    
    # 将协议类型转换为数值
    X['协议类型'] = pd.Categorical(X['协议类型']).codes
    
    # 训练随机森林模型
    n_classes = len(y.unique())
    rf_model = train_random_forest(X, y, n_classes)
    
    # 保存模型
    import joblib
    joblib.dump(rf_model, 'random_forest_model.joblib')
    print("模型已保存为 'random_forest_model.joblib'")

if __name__ == "__main__":
    main()